#pragma once
#include <cctype>
#include <fstream>
namespace proxy
{
    /**
     * @enum proxy_type
     * @brief Enumerates the supported proxy protocol types.
     */
    enum class proxy_type : uint8_t
    {
        socks5,   ///< Standard SOCKS5 proxy (RFC 1928)
        socks5h,  ///< SOCKS5 with remote DNS resolution (behaves same as socks5 at packet level)
        http      ///< HTTP CONNECT proxy (TCP only)
    };

    /**
     * @brief Type-erased interface for TCP proxy servers.
     *
     * Allows storing different tcp_proxy_server template instantiations
     * (e.g., SOCKS5 and HTTP) in the same container.
     */
    struct tcp_proxy_server_base
    {
        virtual ~tcp_proxy_server_base() = default;
        virtual bool start() = 0;
        virtual void stop() = 0;
        [[nodiscard]] virtual uint16_t proxy_port() const = 0;
    };

    /**
     * @brief Concrete type-erased wrapper for a tcp_proxy_server<T>.
     */
    template<typename T>
    struct tcp_proxy_server_wrapper final : tcp_proxy_server_base
    {
        std::unique_ptr<tcp_proxy_server<T>> server;

        explicit tcp_proxy_server_wrapper(std::unique_ptr<tcp_proxy_server<T>> srv)
            : server(std::move(srv)) {}

        bool start() override { return server->start(); }
        void stop() override { server->stop(); }
        [[nodiscard]] uint16_t proxy_port() const override { return server->proxy_port(); }
    };
    /**
     * @class socks_local_router
     * @brief Implements a local router for handling SOCKS proxy traffic.
     *
     * The socks_local_router class manages TCP and UDP redirection, process-to-proxy mapping,
     * and dynamic network adapter filtering for transparent proxying. It integrates with
     * the system's network configuration and logging facilities, and provides mechanisms
     * for deferred process resolution, packet filtering, and proxy server management.
     *
     * Inherits from:
     * - iphelper::network_config_info<socks_local_router>: For network configuration monitoring and callbacks.
     * - netlib::log::logger<socks_local_router>: For logging router events and diagnostics.
     */
    class socks_local_router :  // NOLINT(clang-diagnostic-padded)
        public iphelper::network_config_info<socks_local_router>,
        public netlib::log::logger<socks_local_router>
    {
        // Type alias for the log level used by the logger base class.
        using log_level = netlib::log::log_level;

        /**
         * @brief Alias for the packet filter type from the ndisapi library.
         */
        using packet_filter = ndisapi::queued_multi_interface_packet_filter;

        // Allows the base class 'network_config_info' to access the private CRTP callback.
        friend network_config_info;

        /**
         * @brief Type alias for the SOCKS5 TCP proxy server specialized for IPv4.
         */
        using s5_tcp_proxy_server = tcp_proxy_server<socks5_tcp_proxy_socket<net::ip_address_v4>>;

        /**
         * @brief Type alias for the SOCKS5 UDP proxy server specialized for IPv4.
         */
        using s5_udp_proxy_server = socks5_local_udp_proxy_server<socks5_udp_proxy_socket<net::ip_address_v4>>;

        /**
         * @brief Type alias for the HTTP CONNECT TCP proxy server specialized for IPv4.
         */
        using http_tcp_proxy_server = tcp_proxy_server<http_tcp_proxy_socket<net::ip_address_v4>>;

        /**
         * @brief Redirect target for a TCP flow, including optional hostname recovered from DNS.
         */
        struct tcp_destination_info
        {
            net::ip_endpoint<net::ip_address_v4> endpoint;
            std::optional<std::string> hostname{ std::nullopt };
        };

        /**
         * @brief Key for tracking pending DNS queries until a response arrives.
         */
        struct dns_query_key
        {
            net::ip_address_v4 client_ip;
            uint16_t client_port{};
            net::ip_address_v4 dns_server_ip;
            uint16_t transaction_id{};

            bool operator<(const dns_query_key& other) const noexcept
            {
                return std::tie(client_ip, client_port, dns_server_ip, transaction_id) <
                    std::tie(other.client_ip, other.client_port, other.dns_server_ip, other.transaction_id);
            }
        };

        /**
         * @brief Pending DNS query data captured from an outbound DNS request.
         */
        struct dns_query_value
        {
            unsigned long process_id{};
            bool allow_shared_lookup{ false };
            std::wstring process_identity;
            std::string hostname;
            std::chrono::steady_clock::time_point created_at{ std::chrono::steady_clock::now() };
        };

        /**
         * @brief Key for mapping a resolved IP back to a hostname for a specific process.
         */
        struct dns_resolution_key
        {
            unsigned long process_id{};
            net::ip_address_v4 resolved_ip;

            bool operator<(const dns_resolution_key& other) const noexcept
            {
                return std::tie(process_id, resolved_ip) < std::tie(other.process_id, other.resolved_ip);
            }
        };

        /**
         * @brief Key for mapping a resolved IP back to a hostname for a specific process identity.
         */
        struct dns_process_resolution_key
        {
            std::wstring process_identity;
            net::ip_address_v4 resolved_ip;

            bool operator<(const dns_process_resolution_key& other) const noexcept
            {
                return std::tie(process_identity, resolved_ip) < std::tie(other.process_identity, other.resolved_ip);
            }
        };

        /**
         * @brief Cached DNS resolution data.
         */
        struct dns_resolution_value
        {
            std::string hostname;
            std::chrono::steady_clock::time_point expires_at{ std::chrono::steady_clock::now() };
            bool ambiguous{ false };
        };

        /**
         * @brief Tracks the host-order bounds for a fake IP allocation pool.
         */
        struct fake_ip_pool_range
        {
            uint32_t start_host_order{};
            uint32_t end_host_order{};
            uint32_t next_host_order{};
        };

        /**
         * @brief Stores the assigned fake IP for a hostname.
         */
        struct fake_ip_assignment
        {
            net::ip_address_v4 address;
        };

        /**
         * @brief Stores a mapping of TCP ports to their corresponding IP endpoints.
         */
        std::unordered_map<uint16_t, tcp_destination_info> tcp_mapper_;

        /**
         * @brief Stores the set of UDP ports being mapped.
         */
        std::unordered_set<uint16_t> udp_mapper_;

        /**
         * @brief Mutex to synchronize access to the TCP port mapping.
         */
        std::mutex tcp_mapper_lock_;

        /**
         * @brief Mutex to synchronize access to the UDP port mapping.
         */
        std::mutex udp_mapper_lock_;

        /**
         * @brief Mutex protecting DNS caches.
         */
        std::mutex dns_cache_lock_;

        /**
         * @brief Pending DNS queries waiting for responses.
         */
        std::map<dns_query_key, dns_query_value> pending_dns_queries_;

        /**
         * @brief Resolved DNS names keyed by process and destination IP.
         */
        std::map<dns_resolution_key, dns_resolution_value> resolved_dns_names_;

        /**
         * @brief Resolved DNS names keyed by process identity and destination IP.
         */
        std::map<dns_process_resolution_key, dns_resolution_value> process_resolved_dns_names_;

        /**
         * @brief Shared DNS resolutions for system-owned lookups such as Dnscache.
         */
        std::map<net::ip_address_v4, dns_resolution_value> shared_resolved_dns_names_;

        /**
         * @brief Imported IP-to-hostname mappings loaded from dns/fakeip configuration.
         */
        std::map<net::ip_address_v4, dns_resolution_value> imported_dns_names_;

        /**
         * @brief Imported fake IP ranges used for diagnostics and hostname recovery.
         */
        std::vector<net::ip_subnet<net::ip_address_v4>> fake_ip_ranges_;

        /**
         * @brief Internal fake IP hostname mappings allocated by the DNS hijack path.
         */
        std::map<net::ip_address_v4, dns_resolution_value> fake_ip_dns_names_;

        /**
         * @brief Internal hostname-to-fake-IP allocations.
         */
        std::unordered_map<std::string, fake_ip_assignment> fake_ip_allocations_by_hostname_;

        /**
         * @brief Allocator ranges for fake IP assignment in host byte order.
         */
        std::vector<fake_ip_pool_range> fake_ip_pool_ranges_;

        /**
         * @brief I/O completion port for asynchronous operations.
         */
        netlib::winsys::io_completion_port io_port_;

        /**
         * @brief Optional pcap stream logger for packet capture logging.
         */
        std::optional<pcap::pcap_stream_logger> pcap_logger_;

        /**
         * @brief Vector storing pairs of type-erased TCP proxy servers and UDP proxy servers.
         */
        std::vector<std::pair<std::unique_ptr<tcp_proxy_server_base>, std::unique_ptr<s5_udp_proxy_server>>> proxy_servers_;

        /**
         * @brief Maps proxy indexes to their corresponding process names (sorted by proxy ID).
         */
        std::multimap<size_t, std::wstring> proxy_to_names_;

        /**
         * @brief A list of excluded process names.
         */
        std::vector<std::wstring> excluded_list_;

        /**
         * @brief Shared mutex to protect concurrent access to shared resources.
         */
        std::shared_mutex lock_;

        /**
         * @brief Unique pointer to the TCP redirect object.
         */
        std::unique_ptr<ndisapi::tcp_local_redirect<net::ip_address_v4>> tcp_redirect_{ nullptr };

        /**
         * @brief Unique pointer to the UDP redirect object.
         */
        std::unique_ptr<ndisapi::socks5_udp_local_redirect<net::ip_address_v4>> udp_redirect_{ nullptr };

        /**
         * @brief Unique pointer to the packet filter object.
         */
        std::unique_ptr<packet_filter> packet_filter_{ nullptr };

        /**
         * @brief Static filters for packet filtering.
         */
        ndisapi::static_filters static_filters_;

        /**
         * @brief Process lookup for IPv4 addresses.
         */
        iphelper::process_lookup<net::ip_address_v4> process_lookup_v4_;

        /**
         * @brief Process lookup for IPv6 addresses.
         */
        iphelper::process_lookup<net::ip_address_v6> process_lookup_v6_;

        /**
         * @brief Mutex to protect the set of adapter names that need to be filtered.
         */
        std::shared_mutex adapters_to_filter_lock_;

        /**
         * @brief Set of adapter names that need to be filtered.
         */
        std::unordered_set<std::string> adapters_to_filter_;

        /**
         * @brief Thread for lazy process resolution.
         */
        std::thread process_resolve_thread_;

        /**
         * @brief Queue for holding pointers to intermediate_buffer objects that require process resolution.
         *
         * This queue is used to store buffers that need to be processed by the process resolution thread.
         * Access to this queue is synchronized using process_resolve_buffer_mutex_ and process_resolve_buffer_queue_cv_.
         */
        std::queue<ndisapi::intermediate_buffer_pool::intermediate_buffer_ptr> process_resolve_buffer_queue_;

        /**
         * @brief Mutex to guard access to the process_resolve_buffer_queue_.
         *
         * This mutex ensures thread-safe access to the buffer queue, preventing data races
         * when multiple threads are adding to or removing from the queue.
         */
        mutable std::mutex process_resolve_buffer_mutex_;

        /**
         * @brief Condition variable for synchronizing access to the process_resolve_buffer_queue_.
         *
         * This condition variable is used to notify waiting threads when new buffers are added to the queue,
         * allowing the process resolution thread to efficiently wait for work.
         */
        std::condition_variable process_resolve_buffer_queue_cv_;

        /**
         * @brief Shared pointer to an output stream for PCAP (packet capture) logging.
         *
         * This stream is used to write packet capture data when PCAP logging is enabled.
         * The stream is passed to the constructor and if valid, is used to initialize
         * the pcap_logger_ for packet logging functionality. The shared ownership allows
         * the stream to be safely shared across different components of the router.
         *
         * @see pcap_logger_
         * @see log_packet_to_pcap()
         */
        std::shared_ptr<std::ostream> pcap_log_stream_;

        /**
        * @brief Atomic boolean to track the active status of the router.
        */
        std::atomic_bool is_active_{ false };

        /**
         * @brief Indicates whether DNS hijack is enabled.
         */
        bool dns_hijack_enabled_{ false };

        /**
         * @brief Indicates whether fake IP allocation is enabled.
         */
        bool fake_ip_enabled_{ false };

        static constexpr auto dns_pending_ttl_ = std::chrono::seconds(30);
        static constexpr auto dns_min_resolution_ttl_ = std::chrono::seconds(5);

        static std::string normalize_dns_hostname(std::string hostname)
        {
            while (!hostname.empty() && hostname.back() == '.')
            {
                hostname.pop_back();
            }

            for (auto& ch : hostname)
            {
                ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
            }

            return hostname;
        }

        static bool parse_bool_env_var(const char* const name) noexcept
        {
            char value[16]{};
            const auto length = ::GetEnvironmentVariableA(name, value, static_cast<DWORD>(std::size(value)));

            if (length == 0 || length >= std::size(value))
            {
                return false;
            }

            std::string normalized(value, length);
            for (auto& ch : normalized)
            {
                ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
            }

            return normalized == "1" || normalized == "true" || normalized == "yes" || normalized == "on";
        }

        static net::ip_address_v4 make_ip_address_from_host_order(const uint32_t value) noexcept
        {
            return net::ip_address_v4(htonl(value));
        }

        static std::optional<fake_ip_pool_range> parse_fake_ip_pool_range(const std::string& cidr)
        {
            const auto slash_pos = cidr.find('/');
            if (slash_pos == std::string::npos)
            {
                return std::nullopt;
            }

            const auto [parsed, address] = net::ip_address_v4::from_string(cidr.substr(0, slash_pos));
            if (!parsed)
            {
                return std::nullopt;
            }

            uint32_t prefix_length = 0;

            try
            {
                prefix_length = static_cast<uint32_t>(std::stoul(cidr.substr(slash_pos + 1)));
            }
            catch (...)
            {
                return std::nullopt;
            }

            if (prefix_length > 32)
            {
                return std::nullopt;
            }

            const auto host_order_address = ntohl(address.S_un.S_addr);
            const auto mask = prefix_length == 0
                ? 0U
                : 0xFFFFFFFFU << (32U - prefix_length);
            const auto network = host_order_address & mask;
            const auto broadcast = network | (~mask);
            const auto start = prefix_length >= 31 ? network : network + 1;
            const auto end = prefix_length >= 31 ? broadcast : broadcast - 1;

            if (start > end)
            {
                return std::nullopt;
            }

            return fake_ip_pool_range{ start, end, start };
        }

        void purge_dns_cache_entries_locked()
        {
            const auto now = std::chrono::steady_clock::now();

            for (auto it = pending_dns_queries_.begin(); it != pending_dns_queries_.end();)
            {
                if (now - it->second.created_at > dns_pending_ttl_)
                {
                    it = pending_dns_queries_.erase(it);
                }
                else
                {
                    ++it;
                }
            }

            for (auto it = resolved_dns_names_.begin(); it != resolved_dns_names_.end();)
            {
                if (it->second.expires_at <= now)
                {
                    it = resolved_dns_names_.erase(it);
                }
                else
                {
                    ++it;
                }
            }

            for (auto it = process_resolved_dns_names_.begin(); it != process_resolved_dns_names_.end();)
            {
                if (it->second.expires_at <= now)
                {
                    it = process_resolved_dns_names_.erase(it);
                }
                else
                {
                    ++it;
                }
            }

            for (auto it = shared_resolved_dns_names_.begin(); it != shared_resolved_dns_names_.end();)
            {
                if (it->second.expires_at <= now)
                {
                    it = shared_resolved_dns_names_.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }

        static bool should_allow_shared_dns_lookup(const iphelper::network_process& process)
        {
            return process.id == 0 || process.name == L"SYSTEM" || process.name == L"DNSCACHE";
        }

        static std::wstring get_process_identity_for_dns_lookup(const iphelper::network_process& process)
        {
            if (!process.device_path_name.empty())
            {
                return process.device_path_name;
            }

            if (!process.path_name.empty())
            {
                return process.path_name;
            }

            return process.name;
        }

        void cache_hostname_resolution_locked(std::map<net::ip_address_v4, dns_resolution_value>& cache,
                                             const net::ip_address_v4& resolved_ip,
                                             const std::string& hostname,
                                             const std::chrono::steady_clock::time_point expires_at)
        {
            if (hostname.empty())
            {
                return;
            }

            const auto it = cache.find(resolved_ip);
            if (it == cache.end())
            {
                cache.emplace(resolved_ip, dns_resolution_value{ hostname, expires_at, false });
                return;
            }

            it->second.expires_at = expires_at > it->second.expires_at ? expires_at : it->second.expires_at;

            if (it->second.hostname.empty() || it->second.hostname == hostname)
            {
                it->second.hostname = hostname;
                return;
            }

            it->second.hostname.clear();
            it->second.ambiguous = true;
        }

        void cache_shared_dns_resolution_locked(const net::ip_address_v4& resolved_ip,
                                                const std::string& hostname,
                                                const std::chrono::steady_clock::time_point expires_at)
        {
            cache_hostname_resolution_locked(shared_resolved_dns_names_, resolved_ip, hostname, expires_at);
        }

        void cache_imported_dns_resolution_locked(const net::ip_address_v4& resolved_ip,
                                                  const std::string& hostname)
        {
            cache_hostname_resolution_locked(imported_dns_names_, resolved_ip, hostname,
                std::chrono::steady_clock::time_point::max());
        }

        [[nodiscard]] bool is_fake_ip_range_locked(const net::ip_address_v4& destination_ip) const noexcept
        {
            for (const auto& subnet : fake_ip_ranges_)
            {
                if (subnet.address_in_subnet(destination_ip))
                {
                    return true;
                }
            }

            return false;
        }

        void load_imported_hostname_mappings()
        {
            constexpr auto import_env_var = "PROXIFYRE_HOST_MAPPING_FILE";
            char mapping_file_path[MAX_PATH]{};
            const auto path_length = ::GetEnvironmentVariableA(import_env_var, mapping_file_path, MAX_PATH);

            if (path_length == 0 || path_length >= MAX_PATH)
            {
                return;
            }

            std::ifstream mapping_file(mapping_file_path);
            if (!mapping_file.is_open())
            {
                NETLIB_LOG(log_level::warning, "Failed to open imported hostname mapping file {}", mapping_file_path);
                return;
            }

            size_t imported_host_count = 0;
            size_t imported_fake_range_count = 0;
            std::string line;

            std::scoped_lock lock(dns_cache_lock_);

            while (std::getline(mapping_file, line))
            {
                if (line.empty())
                {
                    continue;
                }

                std::vector<std::string> fields;
                size_t offset = 0;

                while (offset <= line.size())
                {
                    const auto next = line.find('\t', offset);
                    if (next == std::string::npos)
                    {
                        fields.push_back(line.substr(offset));
                        break;
                    }

                    fields.push_back(line.substr(offset, next - offset));
                    offset = next + 1;
                }

                if (fields.empty())
                {
                    continue;
                }

                if ((fields[0] == "dns" || fields[0] == "fakeip") && fields.size() >= 3)
                {
                    if (const auto [parsed, address] = net::ip_address_v4::from_string(fields[1]); parsed)
                    {
                        cache_imported_dns_resolution_locked(address, fields[2]);
                        ++imported_host_count;
                    }
                    else
                    {
                        NETLIB_LOG(log_level::warning,
                                   "Ignoring imported hostname mapping with invalid IPv4 address {}",
                                   fields[1]);
                    }
                }
                else if (fields[0] == "fakeip-range" && fields.size() >= 2)
                {
                    if (const auto subnet = net::ip_subnet<net::ip_address_v4>::from_cidr(fields[1]); subnet.has_value())
                    {
                        fake_ip_ranges_.push_back(subnet.value());
                        ++imported_fake_range_count;
                    }
                    else
                    {
                        NETLIB_LOG(log_level::warning,
                                   "Ignoring imported fake IP range with invalid CIDR {}",
                                   fields[1]);
                    }
                }
            }

            if (imported_host_count != 0 || imported_fake_range_count != 0)
            {
                NETLIB_LOG(log_level::info,
                           "Imported {} hostname mappings and {} fake IP ranges from {}",
                           imported_host_count,
                           imported_fake_range_count,
                           mapping_file_path);
            }
        }

        void load_dns_hijack_configuration()
        {
            constexpr auto dns_hijack_env_var = "PROXIFYRE_DNS_HIJACK";
            constexpr auto fake_ip_enabled_env_var = "PROXIFYRE_FAKEIP_ENABLED";
            constexpr auto fake_ip_ranges_env_var = "PROXIFYRE_FAKEIP_RANGES";

            dns_hijack_enabled_ = parse_bool_env_var(dns_hijack_env_var);
            fake_ip_enabled_ = parse_bool_env_var(fake_ip_enabled_env_var);

            char fake_ip_ranges[4096]{};
            const auto length = ::GetEnvironmentVariableA(
                fake_ip_ranges_env_var,
                fake_ip_ranges,
                static_cast<DWORD>(std::size(fake_ip_ranges)));

            std::scoped_lock lock(dns_cache_lock_);
            fake_ip_ranges_.clear();
            fake_ip_pool_ranges_.clear();

            if (length != 0 && length < std::size(fake_ip_ranges))
            {
                size_t offset = 0;

                while (offset <= length)
                {
                    const auto next_delimiter = std::string_view(fake_ip_ranges, length).find(';', offset);
                    const auto token = next_delimiter == std::string_view::npos
                        ? std::string(fake_ip_ranges + offset, length - offset)
                        : std::string(fake_ip_ranges + offset, next_delimiter - offset);

                    if (!token.empty())
                    {
                        if (const auto subnet = net::ip_subnet<net::ip_address_v4>::from_cidr(token); subnet.has_value())
                        {
                            fake_ip_ranges_.push_back(subnet.value());
                        }

                        if (const auto pool_range = parse_fake_ip_pool_range(token); pool_range.has_value())
                        {
                            fake_ip_pool_ranges_.push_back(pool_range.value());
                        }
                        else
                        {
                            NETLIB_LOG(log_level::warning,
                                "Ignoring fake IP range with invalid CIDR {}",
                                token);
                        }
                    }

                    if (next_delimiter == std::string_view::npos)
                    {
                        break;
                    }

                    offset = next_delimiter + 1;
                }
            }

            if (dns_hijack_enabled_)
            {
                NETLIB_LOG(log_level::info, "DNS hijack is enabled.");
            }

            if (fake_ip_enabled_)
            {
                NETLIB_LOG(log_level::info,
                    "Fake IP is enabled with {} allocation range(s).",
                    fake_ip_pool_ranges_.size());
            }
        }

        std::optional<net::ip_address_v4> allocate_fake_ip_locked(const std::string& hostname)
        {
            if (hostname.empty() || !fake_ip_enabled_)
            {
                return std::nullopt;
            }

            if (const auto it = fake_ip_allocations_by_hostname_.find(hostname);
                it != fake_ip_allocations_by_hostname_.end())
            {
                return it->second.address;
            }

            for (auto& range : fake_ip_pool_ranges_)
            {
                if (range.start_host_order > range.end_host_order)
                {
                    continue;
                }

                auto candidate = range.next_host_order;
                if (candidate < range.start_host_order || candidate > range.end_host_order)
                {
                    candidate = range.start_host_order;
                }

                const auto first_candidate = candidate;
                bool first_iteration = true;

                while (first_iteration || candidate != first_candidate)
                {
                    first_iteration = false;

                    const auto fake_ip = make_ip_address_from_host_order(candidate);
                    if (fake_ip_dns_names_.find(fake_ip) == fake_ip_dns_names_.end())
                    {
                        fake_ip_dns_names_[fake_ip] =
                            dns_resolution_value{ hostname, std::chrono::steady_clock::time_point::max(), false };
                        fake_ip_allocations_by_hostname_[hostname] = fake_ip_assignment{ fake_ip };
                        range.next_host_order = candidate == range.end_host_order ? range.start_host_order : candidate + 1;
                        return fake_ip;
                    }

                    candidate = candidate == range.end_host_order ? range.start_host_order : candidate + 1;
                }
            }

            return std::nullopt;
        }

        bool should_hijack_dns_for_process(const std::shared_ptr<iphelper::network_process>& process)
        {
            if (!process || process->excluded)
            {
                return false;
            }

            if (process->tcp_proxy_port.has_value() || process->udp_proxy_port.has_value())
            {
                return true;
            }

            return get_proxy_port_tcp(process).has_value() || get_proxy_port_udp(process).has_value();
        }

        bool try_hijack_dns_query(ndisapi::intermediate_buffer& buffer,
                                  iphdr* const ip_header,
                                  udphdr* const udp_header,
                                  const std::shared_ptr<iphelper::network_process>& process,
                                  const size_t payload_size)
        {
            if (!dns_hijack_enabled_ || !fake_ip_enabled_ || !should_hijack_dns_for_process(process))
            {
                return false;
            }

            auto* const ethernet_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);
            auto* const dns_payload = reinterpret_cast<uint8_t*>(udp_header + 1);

            if (payload_size < sizeof(dns_header))
            {
                return false;
            }

            auto* const header = reinterpret_cast<dns_header*>(dns_payload);
            if ((ntohs(header->flags) & 0x8000U) != 0 || ntohs(header->qdcount) != 1)
            {
                return false;
            }

            auto offset = sizeof(dns_header);
            std::string hostname;

            if (!parse_dns_name(dns_payload, payload_size, offset, hostname))
            {
                return false;
            }

            hostname = normalize_dns_hostname(std::move(hostname));
            if (hostname.empty() || offset + sizeof(qr_record) > payload_size)
            {
                return false;
            }

            const auto* const question = reinterpret_cast<const qr_record*>(dns_payload + offset);
            const auto question_type = ntohs(question->type);
            const auto question_class = ntohs(question->clas);
            const auto question_end = offset + sizeof(qr_record);
            auto response_size = question_end;
            std::optional<net::ip_address_v4> fake_ip = std::nullopt;

            header->flags = htons(0x8000U | 0x0080U | (ntohs(header->flags) & 0x0100U));
            header->nscount = 0;
            header->arcount = 0;
            header->ancount = 0;

            if (question_class == 1 && question_type == 1)
            {
                std::scoped_lock lock(dns_cache_lock_);
                purge_dns_cache_entries_locked();
                fake_ip = allocate_fake_ip_locked(hostname);

                if (!fake_ip.has_value())
                {
                    return false;
                }

                const uint16_t answer_name = htons(0xC00CU);
                const res_record answer{
                    htons(1),
                    htons(1),
                    htonl(static_cast<uint32_t>(dns_min_resolution_ttl_.count())),
                    htons(sizeof(IN_ADDR))
                };

                memcpy(dns_payload + response_size, &answer_name, sizeof(answer_name));
                response_size += sizeof(answer_name);
                memcpy(dns_payload + response_size, &answer, sizeof(answer));
                response_size += sizeof(answer);
                memcpy(dns_payload + response_size, &fake_ip->S_un.S_addr, sizeof(IN_ADDR));
                response_size += sizeof(IN_ADDR);
                header->ancount = htons(1);
            }

            std::swap(ethernet_header->h_dest, ethernet_header->h_source);
            std::swap(ip_header->ip_dst, ip_header->ip_src);
            std::swap(udp_header->th_dport, udp_header->th_sport);

            udp_header->length = htons(static_cast<uint16_t>(sizeof(udphdr) + response_size));
            ip_header->ip_len = htons(static_cast<uint16_t>(sizeof(DWORD) * ip_header->ip_hl + sizeof(udphdr) + response_size));
            buffer.m_Length = static_cast<DWORD>(
                ETHER_HEADER_LENGTH + sizeof(DWORD) * ip_header->ip_hl + sizeof(udphdr) + response_size);

            CNdisApi::RecalculateUDPChecksum(&buffer);
            CNdisApi::RecalculateIPChecksum(&buffer);

            if (fake_ip.has_value())
            {
                NETLIB_LOG(log_level::info,
                    "Hijacked DNS query for pid {} host {} -> fake IP {}",
                    process ? process->id : 0,
                    hostname,
                    fake_ip.value());
            }
            else
            {
                NETLIB_LOG(log_level::info,
                    "Hijacked DNS query for pid {} host {} with empty response for qtype {}",
                    process ? process->id : 0,
                    hostname,
                    question_type);
            }

            return true;
        }

        bool try_hijack_dns_query_ipv6(ndisapi::intermediate_buffer& buffer,
                                       ipv6hdr* const ip_header,
                                       udphdr* const udp_header,
                                       const std::shared_ptr<iphelper::network_process>& process,
                                       const size_t payload_size)
        {
            if (!dns_hijack_enabled_ || !fake_ip_enabled_ || !should_hijack_dns_for_process(process))
            {
                return false;
            }

            auto* const ethernet_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);
            auto* const dns_payload = reinterpret_cast<uint8_t*>(udp_header + 1);

            if (payload_size < sizeof(dns_header))
            {
                return false;
            }

            auto* const header = reinterpret_cast<dns_header*>(dns_payload);
            if ((ntohs(header->flags) & 0x8000U) != 0 || ntohs(header->qdcount) != 1)
            {
                return false;
            }

            auto offset = sizeof(dns_header);
            std::string hostname;

            if (!parse_dns_name(dns_payload, payload_size, offset, hostname))
            {
                return false;
            }

            hostname = normalize_dns_hostname(std::move(hostname));
            if (hostname.empty() || offset + sizeof(qr_record) > payload_size)
            {
                return false;
            }

            const auto* const question = reinterpret_cast<const qr_record*>(dns_payload + offset);
            const auto question_type = ntohs(question->type);
            const auto question_class = ntohs(question->clas);
            const auto question_end = offset + sizeof(qr_record);
            auto response_size = question_end;
            std::optional<net::ip_address_v4> fake_ip = std::nullopt;

            header->flags = htons(0x8000U | 0x0080U | (ntohs(header->flags) & 0x0100U));
            header->nscount = 0;
            header->arcount = 0;
            header->ancount = 0;

            if (question_class == 1 && question_type == 1)
            {
                std::scoped_lock lock(dns_cache_lock_);
                purge_dns_cache_entries_locked();
                fake_ip = allocate_fake_ip_locked(hostname);

                if (!fake_ip.has_value())
                {
                    return false;
                }

                const uint16_t answer_name = htons(0xC00CU);
                const res_record answer{
                    htons(1),
                    htons(1),
                    htonl(static_cast<uint32_t>(dns_min_resolution_ttl_.count())),
                    htons(sizeof(IN_ADDR))
                };

                memcpy(dns_payload + response_size, &answer_name, sizeof(answer_name));
                response_size += sizeof(answer_name);
                memcpy(dns_payload + response_size, &answer, sizeof(answer));
                response_size += sizeof(answer);
                memcpy(dns_payload + response_size, &fake_ip->S_un.S_addr, sizeof(IN_ADDR));
                response_size += sizeof(IN_ADDR);
                header->ancount = htons(1);
            }

            std::swap(ethernet_header->h_dest, ethernet_header->h_source);
            std::swap(ip_header->ip6_dst, ip_header->ip6_src);
            std::swap(udp_header->th_dport, udp_header->th_sport);

            udp_header->length = htons(static_cast<uint16_t>(sizeof(udphdr) + response_size));
            ip_header->ip6_len = htons(static_cast<uint16_t>(sizeof(udphdr) + response_size));
            buffer.m_Length = static_cast<DWORD>(
                ETHER_HEADER_LENGTH + sizeof(ipv6hdr) + sizeof(udphdr) + response_size);

            net::ipv6_helper::recalculate_tcp_udp_checksum(&buffer);

            if (fake_ip.has_value())
            {
                NETLIB_LOG(log_level::info,
                    "Hijacked IPv6 DNS query for pid {} host {} -> fake IP {}",
                    process ? process->id : 0,
                    hostname,
                    fake_ip.value());
            }
            else
            {
                NETLIB_LOG(log_level::info,
                    "Hijacked IPv6 DNS query for pid {} host {} with empty response for qtype {}",
                    process ? process->id : 0,
                    hostname,
                    question_type);
            }

            return true;
        }

        bool parse_dns_name(const uint8_t* const dns_payload, const size_t payload_size,
                            size_t& offset, std::string& hostname, const size_t depth = 0) const
        {
            if (depth > 8 || offset >= payload_size)
            {
                return false;
            }

            auto current_offset = offset;
            auto first_label = true;

            for (size_t labels = 0; current_offset < payload_size && labels < 128; ++labels)
            {
                const auto length = dns_payload[current_offset];

                if (length == 0)
                {
                    offset = current_offset + 1;
                    return true;
                }

                if ((length & 0xC0U) == 0xC0U)
                {
                    if (current_offset + 1 >= payload_size)
                    {
                        return false;
                    }

                    const auto pointer_offset = static_cast<size_t>(((length & 0x3FU) << 8U)
                        | dns_payload[current_offset + 1]);

                    if (pointer_offset >= payload_size)
                    {
                        return false;
                    }

                    offset = current_offset + 2;
                    auto nested_offset = pointer_offset;
                    std::string suffix;

                    if (!parse_dns_name(dns_payload, payload_size, nested_offset, suffix, depth + 1))
                    {
                        return false;
                    }

                    if (!suffix.empty())
                    {
                        if (!first_label)
                        {
                            hostname.push_back('.');
                        }

                        hostname += suffix;
                    }

                    return true;
                }

                if ((length & 0xC0U) != 0)
                {
                    return false;
                }

                ++current_offset;

                if (current_offset + length > payload_size)
                {
                    return false;
                }

                if (!first_label)
                {
                    hostname.push_back('.');
                }

                hostname.append(reinterpret_cast<const char*>(dns_payload + current_offset), length);
                current_offset += length;
                first_label = false;
            }

            return false;
        }

        void cache_dns_query(const iphdr* const ip_header, const udphdr* const udp_header,
                     const iphelper::network_process& process, const bool allow_shared_lookup,
                     const uint8_t* const dns_payload,
                             const size_t payload_size)
        {
            if (payload_size < sizeof(dns_header))
            {
                return;
            }

            const auto* const header = reinterpret_cast<const dns_header*>(dns_payload);

            if ((ntohs(header->flags) & 0x8000U) != 0 || ntohs(header->qdcount) == 0)
            {
                return;
            }

            auto offset = sizeof(dns_header);
            std::string hostname;

            if (!parse_dns_name(dns_payload, payload_size, offset, hostname) || hostname.empty())
            {
                return;
            }

            hostname = normalize_dns_hostname(std::move(hostname));
            if (hostname.empty())
            {
                return;
            }

            if (offset + sizeof(qr_record) > payload_size)
            {
                return;
            }

            std::scoped_lock lock(dns_cache_lock_);
            purge_dns_cache_entries_locked();

            pending_dns_queries_[dns_query_key{
                net::ip_address_v4(ip_header->ip_src),
                ntohs(udp_header->th_sport),
                net::ip_address_v4(ip_header->ip_dst),
                ntohs(header->id)
            }] = dns_query_value{
                process.id,
                allow_shared_lookup,
                get_process_identity_for_dns_lookup(process),
                hostname,
                std::chrono::steady_clock::now()
            };

            NETLIB_LOG(log_level::debug,
                "Cached DNS query for pid {} identity {} host {} shared={} txid={} via {}:{} -> {}:{}",
                process.id,
                tools::strings::to_string(get_process_identity_for_dns_lookup(process)),
                hostname,
                allow_shared_lookup,
                ntohs(header->id),
                net::ip_address_v4(ip_header->ip_src),
                ntohs(udp_header->th_sport),
                net::ip_address_v4(ip_header->ip_dst),
                ntohs(udp_header->th_dport));
        }

        void cache_dns_response(const iphdr* const ip_header, const udphdr* const udp_header,
                                const uint8_t* const dns_payload, const size_t payload_size)
        {
            if (payload_size < sizeof(dns_header))
            {
                return;
            }

            const auto* const header = reinterpret_cast<const dns_header*>(dns_payload);

            if ((ntohs(header->flags) & 0x8000U) == 0 || ntohs(header->ancount) == 0)
            {
                return;
            }

            std::scoped_lock lock(dns_cache_lock_);
            purge_dns_cache_entries_locked();

            const dns_query_key key{
                net::ip_address_v4(ip_header->ip_dst),
                ntohs(udp_header->th_dport),
                net::ip_address_v4(ip_header->ip_src),
                ntohs(header->id)
            };

            const auto query_it = pending_dns_queries_.find(key);

            if (query_it == pending_dns_queries_.end())
            {
                NETLIB_LOG(log_level::debug,
                    "DNS response had no pending query match for txid={} via {}:{} -> {}:{}",
                    ntohs(header->id),
                    net::ip_address_v4(ip_header->ip_src),
                    ntohs(udp_header->th_sport),
                    net::ip_address_v4(ip_header->ip_dst),
                    ntohs(udp_header->th_dport));
                return;
            }

            auto offset = sizeof(dns_header);

            for (size_t question_index = 0; question_index < ntohs(header->qdcount); ++question_index)
            {
                std::string ignored_hostname;

                if (!parse_dns_name(dns_payload, payload_size, offset, ignored_hostname)
                    || offset + sizeof(qr_record) > payload_size)
                {
                    pending_dns_queries_.erase(query_it);
                    return;
                }

                offset += sizeof(qr_record);
            }

            const auto now = std::chrono::steady_clock::now();
            const auto hostname = normalize_dns_hostname(query_it->second.hostname);
            const auto process_id = query_it->second.process_id;
            const auto allow_shared_lookup = query_it->second.allow_shared_lookup;
            const auto process_identity = query_it->second.process_identity;

            for (size_t answer_index = 0; answer_index < ntohs(header->ancount); ++answer_index)
            {
                std::string ignored_name;

                if (!parse_dns_name(dns_payload, payload_size, offset, ignored_name)
                    || offset + sizeof(res_record) > payload_size)
                {
                    break;
                }

                const auto* const answer = reinterpret_cast<const res_record*>(dns_payload + offset);
                offset += sizeof(res_record);

                const auto rdlength = ntohs(answer->rdlength);

                if (offset + rdlength > payload_size)
                {
                    break;
                }

                if (ntohs(answer->type) == 1 && ntohs(answer->clas) == 1 && rdlength == sizeof(IN_ADDR))
                {
                    IN_ADDR resolved_address{};
                    memcpy(&resolved_address, dns_payload + offset, sizeof(IN_ADDR));

                    auto ttl = std::chrono::seconds(ntohl(answer->ttl));
                    if (ttl < dns_min_resolution_ttl_)
                    {
                        ttl = dns_min_resolution_ttl_;
                    }

                    const auto resolved_ip = net::ip_address_v4(resolved_address);
                    const auto expires_at = now + ttl;

                    resolved_dns_names_[dns_resolution_key{ process_id, resolved_ip }] =
                        dns_resolution_value{ hostname, expires_at, false };

                    if (!process_identity.empty())
                    {
                        process_resolved_dns_names_[dns_process_resolution_key{ process_identity, resolved_ip }] =
                            dns_resolution_value{ hostname, expires_at, false };
                    }

                    if (allow_shared_lookup)
                    {
                        cache_shared_dns_resolution_locked(resolved_ip, hostname, expires_at);
                    }

                    NETLIB_LOG(log_level::debug,
                        "Cached DNS response hostname {} -> {} for pid {} identity {} shared={}",
                        hostname,
                        resolved_ip,
                        process_id,
                        tools::strings::to_string(process_identity),
                        allow_shared_lookup);
                }

                offset += rdlength;
            }

            pending_dns_queries_.erase(query_it);
        }

        std::optional<std::string> lookup_dns_hostname(const iphelper::network_process& process,
                                                       const net::ip_address_v4& destination_ip)
        {
            std::scoped_lock lock(dns_cache_lock_);
            purge_dns_cache_entries_locked();

            if (const auto it = resolved_dns_names_.find(dns_resolution_key{ process.id, destination_ip });
                it != resolved_dns_names_.end())
            {
                NETLIB_LOG(log_level::debug,
                    "Using exact DNS hostname match for pid {} destination {} -> {}",
                    process.id,
                    destination_ip,
                    it->second.hostname);
                return it->second.hostname;
            }

            const auto process_identity = get_process_identity_for_dns_lookup(process);
            if (!process_identity.empty())
            {
                if (const auto it = process_resolved_dns_names_.find(dns_process_resolution_key{ process_identity, destination_ip });
                    it != process_resolved_dns_names_.end())
                {
                    NETLIB_LOG(log_level::debug,
                        "Using process identity DNS hostname fallback for pid {} identity {} destination {} -> {}",
                        process.id,
                        tools::strings::to_string(process_identity),
                        destination_ip,
                        it->second.hostname);
                    return it->second.hostname;
                }
            }

            if (const auto it = fake_ip_dns_names_.find(destination_ip);
                it != fake_ip_dns_names_.end() && !it->second.hostname.empty())
            {
                NETLIB_LOG(log_level::info,
                    "Using fake IP hostname for pid {} and destination {} -> {}",
                    process.id,
                    destination_ip,
                    it->second.hostname);
                return it->second.hostname;
            }

            if (const auto it = imported_dns_names_.find(destination_ip);
                it != imported_dns_names_.end() && !it->second.ambiguous && !it->second.hostname.empty())
            {
                NETLIB_LOG(log_level::debug,
                    "Using imported DNS/fakeip hostname for pid {} and destination {} -> {}",
                    process.id,
                    destination_ip,
                    it->second.hostname);
                return it->second.hostname;
            }

            if (const auto it = shared_resolved_dns_names_.find(destination_ip);
                it != shared_resolved_dns_names_.end() && !it->second.ambiguous && !it->second.hostname.empty())
            {
                NETLIB_LOG(log_level::debug,
                    "Using shared DNS hostname fallback for pid {} and destination {} -> {}",
                    process.id, destination_ip, it->second.hostname);
                return it->second.hostname;
            }

            if (is_fake_ip_range_locked(destination_ip))
            {
                NETLIB_LOG(log_level::debug,
                    "No fake IP hostname match for pid {} identity {} destination {}",
                    process.id,
                    tools::strings::to_string(process_identity),
                    destination_ip);
            }

            NETLIB_LOG(log_level::debug,
                "No DNS hostname match for pid {} identity {} destination {}",
                process.id,
                tools::strings::to_string(process_identity),
                destination_ip);

            return std::nullopt;
        }

    public:
        enum supported_protocols : uint8_t
        {
            tcp,
            udp,
            both
        };

        /**
         * The socks_local_router class constructor, used to set up a local router to handle SOCKS traffic.
         * It creates instances of `tcp_local_redirect`, `socks5_udp_local_redirect` and `queued_packet_filter`
         * for TCP and UDP redirection and packet filtering respectively.
         *
         * @param log_level A netlib::log::log_level object that defines the level of log information to be printed.
         *                  For instance, if log_level > netlib::log::log_level::debug, the router creates a pcap file for capturing network packets.
         * @param log_stream Optional reference to an output stream for logging.
         * @param pcap_log_stream Optional reference to an output stream for pcap logging.
         */
        explicit socks_local_router(const log_level log_level = log_level::error,
                                    std::shared_ptr<std::ostream> log_stream = nullptr,
                                    std::shared_ptr<std::ostream> pcap_log_stream = nullptr) :
                                    logger(log_level, std::move(log_stream)),
                                    static_filters_{ true, true, log_level_, log_stream_ },
                                    process_lookup_v4_{ log_level_, log_stream_ },
                                    process_lookup_v6_{ log_level_, log_stream_ },
                                    pcap_log_stream_(std::move(pcap_log_stream))
        {
            using namespace std::string_literals;

            if (pcap_log_stream_) {
                pcap_logger_.emplace(*pcap_log_stream_);
            }

            load_dns_hijack_configuration();

            // Initialize TCP and UDP redirect objects
            tcp_redirect_ = std::make_unique<ndisapi::tcp_local_redirect<net::ip_address_v4>>(log_level_, log_stream);
            udp_redirect_ = std::make_unique<ndisapi::socks5_udp_local_redirect<net::ip_address_v4>>(
                log_level_, log_stream);

            // Initialize packet filter
            packet_filter_ = std::make_unique<packet_filter>(
                nullptr,
                [this](HANDLE, ndisapi::intermediate_buffer& buffer)
                {
                    auto* const ethernet_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);
                    const auto destination_mac = net::mac_address(ethernet_header->h_dest);
                    const auto ether_type = ntohs(ethernet_header->h_proto);

                    log_packet_to_pcap(buffer);

                    if (ether_type == ETH_P_IP)
                    {
                        const auto* const ip_header = reinterpret_cast<iphdr_ptr>(ethernet_header + 1);

                        if (ip_header->ip_p == IPPROTO_UDP)
                        {
                            // skip broadcast and multicast UDP packets
                            if (destination_mac.is_broadcast() || destination_mac.is_multicast())
                            {
                                return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };
                            }

                            if (const auto result = process_udp_packet(buffer, false))
                            {
                                return result.value();
                            }
                            // Queue for the later processing
                            if (auto allocated_buffer = ndisapi::intermediate_buffer_pool::instance().allocate(buffer))
                            {
                                {
                                    std::scoped_lock lock(process_resolve_buffer_mutex_);
                                    process_resolve_buffer_queue_.push(std::move(allocated_buffer));
                                }
                                process_resolve_buffer_queue_cv_.notify_one();
                            }
                            else
                            {
                                // Handle the error, e.g., log it or take corrective action
                                NETLIB_LOG(log_level::error, "Failed to allocate buffer.");
                            }
                            return packet_filter::packet_action{ packet_filter::packet_action::action_type::drop };
                        }

                        if (ip_header->ip_p == IPPROTO_TCP)
                        {
                            if (const auto result = process_tcp_packet(buffer, false))
                            {
                                return result.value();
                            }
                            // Queue for the later processing
                            if (auto allocated_buffer = ndisapi::intermediate_buffer_pool::instance().allocate(buffer))
                            {
                                {
                                    std::scoped_lock lock(process_resolve_buffer_mutex_);
                                    process_resolve_buffer_queue_.push(std::move(allocated_buffer));
                                }
                                process_resolve_buffer_queue_cv_.notify_one();
                            }
                            else
                            {
                                // Handle the error, e.g., log it or take corrective action
                                NETLIB_LOG(log_level::error, "Failed to allocate buffer.");
                            }
                            return packet_filter::packet_action{ packet_filter::packet_action::action_type::drop };
                        }
                    }

                    if (ether_type == ETH_P_IPV6)
                    {
                        if (destination_mac.is_multicast())
                        {
                            return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };
                        }

                        if (const auto result = process_udp_packet_v6(buffer, false))
                        {
                            return result.value();
                        }

                        if (auto allocated_buffer = ndisapi::intermediate_buffer_pool::instance().allocate(buffer))
                        {
                            {
                                std::scoped_lock lock(process_resolve_buffer_mutex_);
                                process_resolve_buffer_queue_.push(std::move(allocated_buffer));
                            }
                            process_resolve_buffer_queue_cv_.notify_one();
                        }
                        else
                        {
                            NETLIB_LOG(log_level::error, "Failed to allocate IPv6 buffer.");
                        }

                        return packet_filter::packet_action{ packet_filter::packet_action::action_type::drop };
                    }

                    return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };
                });

            // Set up ICMP filter to pass all ICMP traffic
            ndisapi::filter<net::ip_address_v4> icmp_filter;
            icmp_filter
                .set_action(ndisapi::action_t::pass)
                .set_direction(ndisapi::direction_t::both)
                .set_protocol(IPPROTO_ICMP);

            // Add the ICMP filter to the static filters list
            static_filters_.add_filter_back(icmp_filter);
        }

        /**
         * Destructor for the socks_local_router class.
         * It ensures the router stops properly when an instance of the class is destroyed.
         */
        ~socks_local_router() override
        {
            try
            {
                if (is_active_.load(std::memory_order_acquire))
                {
                    NETLIB_DEBUG("Destructor calling stop()");
                    stop();
                }
            }
            catch (const std::exception& e)
            {
                // Log but don't throw from destructor
                // Throwing from destructor causes std::terminate/abort
                NETLIB_ERROR("Exception in ~socks_local_router::stop(): {}", e.what());
            }
            catch (...)
            {
                // Catch any other exceptions to prevent abort
                NETLIB_ERROR("Unknown exception in ~socks_local_router::stop()");
            }
        }

        /**
         * Copy constructor is deleted to prevent copying of the socks_local_router instance.
         */
        socks_local_router(const socks_local_router& other) = delete;

        /**
         * Move constructor is deleted to prevent moving of the socks_local_router instance.
         */
        socks_local_router(socks_local_router&& other) = delete;

        /**
         * Copy assignment operator is deleted to prevent copying of the socks_local_router instance.
         */
        socks_local_router& operator=(const socks_local_router& other) = delete;

        /**
         * Move assignment operator is deleted to prevent moving of the socks_local_router instance.
         */
        socks_local_router& operator=(socks_local_router&& other) = delete;

        /**
         * @brief Starts the proxies and the network filter if they are inactive.
         *
         * This function first checks whether the operation is inactive or not. If it is active, the function
         * returns false. If it is inactive, it sets the active flag to true, starts the thread pool associated
         * with the I/O completion port, and starts all the TCP and UDP proxies. Then, it updates the network
         * configuration and starts the network filter if the network configuration update was successful.
         * Finally, it sets up notifications for IP interface changes.
         *
         * @return false if the operation was already active at the start of this function, otherwise true
         *         (even if there were errors starting the operation).
         */
        bool start()
        {
            if (auto expected = false; !is_active_.compare_exchange_strong(expected, true))
            {
                NETLIB_LOG(log_level::error, "Filter is already active!");
                return false;
            }

            if (!packet_filter_)
            {
                NETLIB_LOG(log_level::error, "Packet filter is not initialized!");
                return false;
            }

            if (!this->set_notify_ip_interface_change())
            {
                NETLIB_LOG(
                    log_level::error,
                    "set_notify_ip_interface_change has failed, lasterror: {}",
                    GetLastError());
            }

            {
                std::shared_lock lock(lock_);

                // Start thread pool
                io_port_.start_thread_pool();

                // Start proxies
                for (auto& [tcp, udp] : proxy_servers_)
                {
                    if (tcp)
                    {
                        if (!tcp->start())
                        {
                            NETLIB_LOG(log_level::error, "Failed to start TCP proxy on port: {}", tcp->proxy_port());
                        }
                    }

                    if (udp)
                    {
                        if (!udp->start())
                        {
                            NETLIB_LOG(log_level::error, "Failed to start UDP proxy on port: {}", udp->proxy_port());
                        }
                    }
                }
            }

            process_resolve_thread_ = std::thread(&socks_local_router::process_resolve_thread_proc, this);

            // Update network configuration and start filter
            update_network_configuration();
            if (!packet_filter_->start_filter())
            {
                NETLIB_LOG(log_level::error, "Failed to start NDIS packet filter");

                // Attempt to cancel notification of IP interface changes
                if (!this->cancel_notify_ip_interface_change())
                {
                    // Log an error if cancelling notification of IP interface changes failed
                    NETLIB_LOG(
                        log_level::error, "cancel_notify_ip_interface_change has failed, lasterror: {}",
                        GetLastError());

                    std::shared_lock lock(lock_);

                    // Stop all proxies
                    for (auto& [tcp, udp] : proxy_servers_)
                    {
                        // Stop TCP proxy
                        if (tcp)
                            tcp->stop();

                        // Stop UDP proxy
                        if (udp)
                            udp->stop();
                    }

                    // Stop the thread pool associated with the I/O completion port
                    io_port_.stop_thread_pool();

                    is_active_.store(false);

                    process_resolve_buffer_queue_cv_.notify_all();

                    if (process_resolve_thread_.joinable())
                        process_resolve_thread_.join();
                }
            }

            return is_active_;
        }

        /**
         * @brief Stops the proxies and the network filter if they are active.
         *
         * This function first checks whether the operation is active or not. If it is inactive, the function
         * returns false. If it is active, it sets the active flag to false, cancels notifications for IP
         * interface changes, stops the network filter, and stops all the TCP and UDP proxies. Finally,
         * it stops the thread pool associated with the I/O completion port.
         *
         * @return false if the operation was not active at the start of this function, otherwise true
         *         (even if there were errors stopping the operation).
         */
        bool stop()
        {
            // A flag to indicate whether the operation was active or not.
            // If the value of is_active_ was already false, this function returns false
            if (auto expected = true; !is_active_.compare_exchange_strong(expected, false))
                return false;

            // Step 1: Stop the packet filter FIRST
            // This prevents new packets from being processed and queued
            NETLIB_DEBUG("Stopping packet filter");
            packet_filter_->stop_filter();

            // Step 2: Signal and join the process resolve thread
            // This ensures no more packets are being queued for processing
            NETLIB_DEBUG("Stopping process resolve thread");
            process_resolve_buffer_queue_cv_.notify_all();

            if (process_resolve_thread_.joinable())
                process_resolve_thread_.join();

            // Step 3: Stop all redirect objects FIRST to stop their cleanup threads
            // CRITICAL: Stop redirects before stopping proxies to ensure cleanup threads finish
            NETLIB_DEBUG("Stopping redirect objects");

            if (tcp_redirect_)
            {
                tcp_redirect_->stop();  // This should join the cleanup thread
            }

            if (udp_redirect_)
            {
                udp_redirect_->stop();  // This should join the cleanup thread
            }

            // Step 4: Stop all proxy servers WITHOUT holding lock_
            // CRITICAL: We must NOT hold lock_ while calling stop() or during destruction
            // because the cleanup threads inside the proxies need to acquire the same lock

            NETLIB_DEBUG("Stopping {} IPv4 proxy pairs", proxy_servers_.size());

            // Stop all IPv4 proxies without holding lock_
            for (size_t i = 0; i < proxy_servers_.size(); ++i)
            {
                if (proxy_servers_[i].first)
                {
                    NETLIB_DEBUG("Stopping IPv4 TCP proxy #{} on port {}", i, proxy_servers_[i].first->proxy_port());
                    proxy_servers_[i].first->stop();
                }

                if (proxy_servers_[i].second)
                {
                    NETLIB_DEBUG("Stopping IPv4 UDP proxy #{} on port {}", i, proxy_servers_[i].second->proxy_port());
                    proxy_servers_[i].second->stop();
                }
            }

            // Step 5: Stop the IOCP thread pool
            // At this point, all handlers registered by the proxy servers have been
            // unregistered by their respective stop() methods, so no new completions
            // will invoke callbacks that access destroyed objects.
            NETLIB_DEBUG("Stopping IOCP thread pool");
            io_port_.stop_thread_pool();

            // Step 6: Cancel IP interface change notifications
            // Attempt to cancel notification of IP interface changes
            if (!this->cancel_notify_ip_interface_change())
            {
                // Log an error if cancelling notification of IP interface changes failed
                NETLIB_ERROR("cancel_notify_ip_interface_change has failed, lasterror: {}",
                    GetLastError());
            }

            // Step 7: Wait for any in-flight callbacks to complete
            // The callback increments notify_ip_interface_ref_ on entry and decrements on exit.
            // We wait with timeout to prevent indefinite hangs if something goes wrong.
            NETLIB_DEBUG("Waiting for network interface callbacks to complete");

            using namespace std::chrono_literals;
            constexpr auto max_wait_duration = 5s;  // Maximum time to wait for callbacks
            constexpr auto initial_sleep = 1ms;
            constexpr auto max_sleep = 100ms;

            const auto start_time = std::chrono::steady_clock::now();
            auto current_sleep = initial_sleep;

            while (!this->notify_ip_interface_can_unload())
            {
                if (const auto elapsed = std::chrono::steady_clock::now() - start_time; elapsed >= max_wait_duration)
                {
                    NETLIB_WARNING("Timeout waiting for network interface callbacks to complete after {} seconds. "
                        "Proceeding with shutdown - potential resource leak or callback still in-flight.",
                        std::chrono::duration_cast<std::chrono::seconds>(elapsed).count());
                    break;
                }

                // Exponential backoff to reduce CPU usage while waiting
                std::this_thread::sleep_for(current_sleep);
                current_sleep = std::min(current_sleep * 2, max_sleep);
            }

            if (this->notify_ip_interface_can_unload())
            {
                NETLIB_DEBUG("All network interface callbacks completed");
            }

            NETLIB_INFO("socks_local_router stopped successfully");

            // Return the current active status (which should now be false)
            return !is_active_;
        }

        /**
         * @brief Enables LAN traffic bypass by adding pass-through filters.
         *
         * When called, traffic to/from local network ranges (10.x.x.x, 172.16.x.x-172.31.x.x,
         * 192.168.x.x, 224.0.0.x, 169.254.x.x) will pass through without being proxied.
         *
         * @note This must be called before start() to take effect.
         */
        void set_bypass_lan() noexcept
        {
            add_lan_passover_filters_v4();

            if (dns_hijack_enabled_)
            {
                add_lan_dns_redirect_filters_v4();
            }
        }

        /**
         * Checks whether the associated driver is loaded or not.
         * @return boolean representing the load status of the driver (true if loaded, false if not).
         */
        bool is_driver_loaded() const
        {
            return packet_filter_->IsDriverLoaded();
        }

        /**
         * Add a SOCKS5 proxy and optionally starts it.
         * @param endpoint string representing the endpoint of the SOCKS5 proxy server.
         * @param protocols enum representing the protocols to be proxied.
         * @param cred_pair optional pair of strings representing username and password for authentication.
         * @param start boolean flag to start the proxy server after creating it.
         * @return an optional value containing the index of the added proxy server if successful, std::nullopt otherwise.
         */
        std::optional<size_t> add_socks5_proxy(
            const std::string& endpoint,
            const supported_protocols protocols,
            const std::optional<std::pair<std::string, std::string>>& cred_pair,
            const bool start = false
        )
        {
            using namespace std::string_literals;

            // Parse the endpoint to an IP address and port number
            auto proxy_endpoint = parse_endpoint(endpoint);

            // If parsing failed, log the error and return nullopt
            if (!proxy_endpoint)
            {
                NETLIB_LOG(log_level::error, "Failed to parse the proxy endpoint {}", endpoint);
                return {};
            }

            // Construct filter objects for the TCP and UDP traffic to and from the proxy server
            // These filters are used to decide which packets to pass or drop
            // They are configured to match packets based on their source/destination IP and port numbers
            // and their protocol (TCP or UDP)
            auto create_filter = [](const uint8_t protocol, const ndisapi::direction_t direction,
                const net::ip_address_v4& address, const uint16_t port)
            {
                ndisapi::filter<net::ip_address_v4> filter;
                filter.set_protocol(protocol)
                    .set_direction(direction)
                    .set_action(ndisapi::action_t::pass)
                    .set_dest_address(net::ip_subnet{ address, net::ip_address_v4{"255.255.255.255"} })
                    .set_dest_port(std::make_pair(port, port));
                return filter;
            };

            const auto tcp_out_filter = create_filter(IPPROTO_TCP, ndisapi::direction_t::out, proxy_endpoint.value().ip,
                                                      proxy_endpoint.value().port);
            const auto tcp_in_filter = create_filter(IPPROTO_TCP, ndisapi::direction_t::in, proxy_endpoint.value().ip,
                                                     proxy_endpoint.value().port);
            const auto udp_out_filter = create_filter(IPPROTO_UDP, ndisapi::direction_t::out, proxy_endpoint.value().ip,
                                                      proxy_endpoint.value().port);
            const auto udp_in_filter = create_filter(IPPROTO_UDP, ndisapi::direction_t::in, proxy_endpoint.value().ip,
                                                     proxy_endpoint.value().port);

            // Add the filters to a filter list
            // Apply all the filters to the network traffic
            if (protocols == both || protocols == udp)
            {
                static_filters_.add_filter_back(tcp_out_filter);
                static_filters_.add_filter_back(tcp_in_filter);
                static_filters_.add_filter_back(udp_out_filter);
                static_filters_.add_filter_back(udp_in_filter);
            }
            else if (protocols == tcp)
            {
                static_filters_.add_filter_back(tcp_out_filter);
                static_filters_.add_filter_back(tcp_in_filter);
            }

            try
            {
                // Create TCP and UDP proxy server objects and start them if required

                auto socks_tcp_proxy_server = (protocols == both || protocols == tcp)
                                                  ? std::make_unique<s5_tcp_proxy_server>(
                                                      0, io_port_, [this, endpoint = proxy_endpoint.value(), cred_pair](
                                                      const net::ip_address_v4 address, const uint16_t port)->
                                                      std::tuple<net::ip_address_v4, uint16_t, std::unique_ptr<
                                                                     s5_tcp_proxy_server::negotiate_context_t>>
                                                      {
                                                          std::scoped_lock lock(tcp_mapper_lock_);

                                                          if (const auto it = tcp_mapper_.find(port); it != tcp_mapper_.
                                                              end())
                                                          {
                                                              NETLIB_LOG(log_level::info,
                                                                        "TCP Redirect entry was found for the {} : {} is {} : {}",
                                                                        address, port, net::ip_address_v4{it->second.endpoint.ip}, it->second.endpoint.port);

                                                              auto remote_address = it->second.endpoint.ip;
                                                              auto remote_port = it->second.endpoint.port;
                                                              auto destination_hostname = it->second.hostname;

                                                              tcp_mapper_.erase(it);

                                                              return std::make_tuple(endpoint.ip, endpoint.port,
                                                                  std::make_unique<
                                                                      s5_tcp_proxy_server::negotiate_context_t>(
                                                                      remote_address, remote_port,
                                                                      cred_pair
                                                                          ? std::optional(cred_pair.value().first)
                                                                          : std::nullopt,
                                                                      cred_pair
                                                                          ? std::optional(cred_pair.value().second)
                                                                          : std::nullopt,
                                                                      destination_hostname));
                                                          }

                                                          return std::make_tuple(net::ip_address_v4{}, 0, nullptr);
                                                      }, log_level_, log_stream_)
                                                  : nullptr;

                auto socks_udp_proxy_server = (protocols == both || protocols == udp)
                                                  ? std::make_unique<s5_udp_proxy_server>(
                                                      0, io_port_, [this, endpoint = proxy_endpoint.value(), cred_pair](
                                                      const net::ip_address_v4 address, const uint16_t port)->
                                                      std::tuple<net::ip_address_v4, uint16_t, std::unique_ptr<
                                                                     s5_udp_proxy_server::negotiate_context_t>>
                                                      {
                                                          std::scoped_lock lock(udp_mapper_lock_);

                                                          if (const auto it = udp_mapper_.find(port); it != udp_mapper_.
                                                              end())
                                                          {
                                                              NETLIB_LOG(log_level::info,
                                                                        "UDP Redirect entry was found for the {} : {}",
                                                                        address, port);

                                                              udp_mapper_.erase(it);

                                                              return std::make_tuple(endpoint.ip, endpoint.port,
                                                                  std::make_unique<
                                                                      s5_udp_proxy_server::negotiate_context_t>(
                                                                      net::ip_address_v4{}, 0,
                                                                      cred_pair
                                                                          ? std::optional(cred_pair.value().first)
                                                                          : std::nullopt,
                                                                      cred_pair
                                                                          ? std::optional(cred_pair.value().second)
                                                                          : std::nullopt));
                                                          }

                                                          return std::make_tuple(net::ip_address_v4{}, 0, nullptr);
                                                      }, log_level_, log_stream_)
                                                  : nullptr;

                if (start) // optionally start proxies
                {
                    // If successful in starting the servers, log the local listening ports
                    if (socks_tcp_proxy_server)
                    {
                        if (!socks_tcp_proxy_server->start())
                        {
                            NETLIB_LOG(log_level::error, "Failed to start TCP SOCKS5 proxy {}", endpoint);
                            return {};
                        }

                        NETLIB_LOG(log_level::info,
                                  "Local TCP proxy for {} is listening port: {}", endpoint, socks_tcp_proxy_server->proxy_port());
                    }

                    if (socks_udp_proxy_server)
                    {
                        if (!socks_udp_proxy_server->start())
                        {
                            NETLIB_LOG(log_level::error, "Failed to start UDP SOCKS5 proxy {}", endpoint);
                            return {};
                        }

                        NETLIB_LOG(log_level::info,
                                  "Local UDP proxy for {} is listening port: {}", endpoint, socks_udp_proxy_server->proxy_port());
                    }
                }

                // Lock the mutex to safely add the proxy servers to the shared data structure
                std::scoped_lock lock(lock_);

                std::unique_ptr<tcp_proxy_server_base> tcp_wrapper = socks_tcp_proxy_server
                    ? std::make_unique<tcp_proxy_server_wrapper<socks5_tcp_proxy_socket<net::ip_address_v4>>>(
                        std::move(socks_tcp_proxy_server))
                    : nullptr;

                proxy_servers_.emplace_back(
                    std::move(tcp_wrapper), std::move(socks_udp_proxy_server));

                return proxy_servers_.size() - 1; // Return the index of the added proxy server
            }
            catch (const std::exception& e)
            {
                NETLIB_LOG(log_level::error, "An exception was thrown while adding SOCKS5 proxy {} : {}",
                          endpoint, e.what());
            }

            return {}; // Return nullopt in case of error or exception
        }

        /**
         * Add an HTTP CONNECT proxy and optionally starts it.
         * HTTP CONNECT only supports TCP tunneling - no UDP support.
         * @param endpoint string representing the endpoint of the HTTP proxy server.
         * @param cred_pair optional pair of strings representing username and password for Proxy-Authorization.
         * @param start boolean flag to start the proxy server after creating it.
         * @return an optional value containing the index of the added proxy server if successful, std::nullopt otherwise.
         */
        std::optional<size_t> add_http_proxy(
            const std::string& endpoint,
            const std::optional<std::pair<std::string, std::string>>& cred_pair,
            const bool start = false
        )
        {
            using namespace std::string_literals;

            auto proxy_endpoint = parse_endpoint(endpoint);

            if (!proxy_endpoint)
            {
                NETLIB_LOG(log_level::error, "Failed to parse the HTTP proxy endpoint {}", endpoint);
                return {};
            }

            // HTTP CONNECT only supports TCP
            auto create_filter = [](const uint8_t protocol, const ndisapi::direction_t direction,
                const net::ip_address_v4& address, const uint16_t port)
            {
                ndisapi::filter<net::ip_address_v4> filter;
                filter.set_protocol(protocol)
                    .set_direction(direction)
                    .set_action(ndisapi::action_t::pass)
                    .set_dest_address(net::ip_subnet{ address, net::ip_address_v4{"255.255.255.255"} })
                    .set_dest_port(std::make_pair(port, port));
                return filter;
            };

            const auto tcp_out_filter = create_filter(IPPROTO_TCP, ndisapi::direction_t::out, proxy_endpoint.value().ip,
                                                      proxy_endpoint.value().port);
            const auto tcp_in_filter = create_filter(IPPROTO_TCP, ndisapi::direction_t::in, proxy_endpoint.value().ip,
                                                     proxy_endpoint.value().port);

            static_filters_.add_filter_back(tcp_out_filter);
            static_filters_.add_filter_back(tcp_in_filter);

            try
            {
                auto http_proxy_server_ptr = std::make_unique<http_tcp_proxy_server>(
                    0, io_port_, [this, endpoint = proxy_endpoint.value(), cred_pair](
                    const net::ip_address_v4 address, const uint16_t port)->
                    std::tuple<net::ip_address_v4, uint16_t, std::unique_ptr<
                                   http_tcp_proxy_server::negotiate_context_t>>
                    {
                        std::scoped_lock lock(tcp_mapper_lock_);

                        if (const auto it = tcp_mapper_.find(port); it != tcp_mapper_.end())
                        {
                            NETLIB_LOG(log_level::info,
                                      "HTTP TCP Redirect entry was found for the {} : {} is {} : {}",
                                      address, port, net::ip_address_v4{it->second.endpoint.ip}, it->second.endpoint.port);

                            auto remote_address = it->second.endpoint.ip;
                            auto remote_port = it->second.endpoint.port;
                            auto destination_hostname = it->second.hostname;

                            tcp_mapper_.erase(it);

                            return std::make_tuple(endpoint.ip, endpoint.port,
                                std::make_unique<http_tcp_proxy_server::negotiate_context_t>(
                                    remote_address, remote_port,
                                    cred_pair
                                        ? std::optional(cred_pair.value().first)
                                        : std::nullopt,
                                    cred_pair
                                        ? std::optional(cred_pair.value().second)
                                        : std::nullopt,
                                    destination_hostname));
                        }

                        return std::make_tuple(net::ip_address_v4{}, 0, nullptr);
                    }, log_level_, log_stream_);

                if (start)
                {
                    if (http_proxy_server_ptr)
                    {
                        if (!http_proxy_server_ptr->start())
                        {
                            NETLIB_LOG(log_level::error, "Failed to start HTTP CONNECT proxy {}", endpoint);
                            return {};
                        }

                        NETLIB_LOG(log_level::info,
                                  "Local HTTP TCP proxy for {} is listening port: {}", endpoint, http_proxy_server_ptr->proxy_port());
                    }
                }

                std::scoped_lock lock(lock_);

                std::unique_ptr<tcp_proxy_server_base> tcp_wrapper =
                    std::make_unique<tcp_proxy_server_wrapper<http_tcp_proxy_socket<net::ip_address_v4>>>(
                        std::move(http_proxy_server_ptr));

                proxy_servers_.emplace_back(std::move(tcp_wrapper), nullptr);

                return proxy_servers_.size() - 1;
            }
            catch (const std::exception& e)
            {
                NETLIB_LOG(log_level::error, "An exception was thrown while adding HTTP proxy {} : {}",
                          endpoint, e.what());
            }

            return {};
        }

        /**
         * Associates a process name to a specific proxy ID. This function is thread-safe.
         * @param process_name the name of the process to associate with a proxy
         * @param proxy_id the ID of the proxy server to associate with the process
         * @return True if the association was successful, False otherwise
         */
        bool associate_process_name_to_proxy(const std::wstring& process_name, const size_t proxy_id)
        {
            // The lock_guard object acquires the lock in a safe manner,
            // ensuring it gets released even if an exception is thrown.
            std::scoped_lock lock(lock_);

            // Check if the provided proxy ID is within the range of available proxies
            if (proxy_id >= proxy_servers_.size())
            {
                NETLIB_LOG(log_level::error,
                    "associate_process_name_to_proxy: proxy index is out of range!");
                return false; // Return false since the proxy_id is out of range
            }

            try
            {
                // Associate the given process name to the specified proxy ID.
                proxy_to_names_.emplace(proxy_id, to_upper(process_name));
            }
            catch (const std::exception& e) {
                NETLIB_LOG(log_level::error, "Exception associating process name to proxy: {}", e.what());
                return false; // Return false if any exception occurs during the association
            }
            catch (...) {
                NETLIB_LOG(log_level::error, "Unknown exception associating process name to proxy.");
                return false;
            }

            return true; // Return true to indicate the association was successful
        }

        /**
         * @brief Adds a process name to the exclusion list. This function is thread-safe.
         * @param excluded_entry the name of the process to exclude
         * @return True if exclusion was successful, otherwise false
         */
        bool exclude_process_name(const std::wstring& excluded_entry) noexcept
        {
            // The lock_guard makes this function thread-safe against other operations using `lock_`.
            std::scoped_lock lock(lock_);

            try
            {
                // Append the excluded entry
                excluded_list_.push_back(to_upper(excluded_entry));
            }
            catch (const std::exception& e) {
                NETLIB_LOG(log_level::error, "Exception excluding process name: {}", e.what());
                return false;
            }
            catch (...) {
                NETLIB_LOG(log_level::error, "Unknown exception excluding process name.");
                return false;
            }

            return true;
        }

        /**
         * Parses a string to construct a network endpoint, consisting of an IPv4 address and a port number.
         * The format of the string is expected to be "IP:PORT".
         * @param endpoint The string representation of the network endpoint.
         * @return A std::optional containing a net::ip_endpoint<net::ip_address_v4> object if parsing is successful,
         *         or an empty std::optional otherwise.
         */
        static std::optional<net::ip_endpoint<net::ip_address_v4>> parse_endpoint(const std::string& endpoint)
        {
            net::ip_endpoint<net::ip_address_v4> result_endpoint;

            // Locate the ':' character in the string. This separates the IP address and port.
            if (const auto pos = endpoint.find(':'); pos != std::string::npos)
            {
                // Extract and validate the IP address.
                auto [result_v4, address_v4] = net::ip_address_v4::from_string(endpoint.substr(0, pos));

                // Extract and validate the port number.
                if (auto [p, ec] = std::from_chars(endpoint.data() + pos + 1, endpoint.data() + endpoint.size(),
                                                   result_endpoint.port); ec == std::errc())
                {
                    if (result_v4)
                    {
                        // If the IP address is valid, assign it to the result endpoint.
                        result_endpoint.ip = address_v4;
                    }
                    else
                    {
                        // If the IP address is not valid, resolve it using the getaddrinfo function.
                        addrinfo* resulted_address_info = nullptr;
                        addrinfo hints{};

                        ZeroMemory(&hints, sizeof(hints));
                        hints.ai_family = AF_INET;
                        hints.ai_socktype = SOCK_STREAM;
                        hints.ai_protocol = IPPROTO_TCP;

                        if (const auto ret_val = getaddrinfo(endpoint.substr(0, pos).c_str(),
                                                             std::to_string(result_endpoint.port).c_str(), &hints,
                                                             &resulted_address_info); ret_val == 0)
                        {
                            for (const auto* ptr = resulted_address_info; ptr != nullptr; ptr = ptr->ai_next)
                            {
                                if (ptr->ai_family == AF_INET)
                                {
                                    const auto* const ipv4 = reinterpret_cast<sockaddr_in*>(ptr->ai_addr);
                                    result_endpoint.ip = net::ip_address_v4(ipv4->sin_addr);
                                    break;
                                }
                            }
                            freeaddrinfo(resulted_address_info);
                        }
                    }
                }
            }

            // If the IP address is not default, return the result endpoint.
            if (result_endpoint.ip != net::ip_address_v4{})
                return result_endpoint;

            // Otherwise, return an empty std::optional.
            return {};
        }

    private:
        /// <summary>
        /// Converts std::wstring to upper case
        /// </summary>
        /// <param name="str">wide char string to convert</param>
        /// <returns>resulted wide char string</returns>
        static std::wstring to_upper(const std::wstring& str)
        {
            std::wstring upper_case;
            std::ranges::transform(str, std::back_inserter(upper_case), toupper);
            return upper_case;
        }

        /**
         * @brief Matches an application name pattern against the process details with exclusion support.
         *
         * This function performs a two-stage matching process:
         * 1. First, it checks if the process should be excluded based on the exclusion list
         * 2. Then, it performs pattern matching if the process is not excluded
         *
         * For both exclusion checking and pattern matching, the function uses intelligent field selection:
         * - If the pattern/exclusion entry contains path separators ("/" or "\\"), it matches against the process's full path_name
         * - If the pattern/exclusion entry contains no path separators, it matches against the process's name only
         *
         * The pattern matching is performed case-insensitively using substring matching.
         * The function automatically excludes the current process (by process ID) to prevent self-matching.
         *
         * @param app The application name or pattern to check against the process details.
         *            Can be either a simple process name (e.g., "notepad.exe") or a path-based pattern (e.g., "C:\\Windows\\System32\\notepad.exe").
         * @param process The process details to check against the application pattern.
         *                Must contain valid name and path_name fields for comparison.
         * @return true if the process details match the application pattern and are not in the exclusion list,
         *              and are not the current process; false otherwise.
         *
         * @note This function does not perform caching. Caching is handled at a higher level by the
         *       get_proxy_port_tcp() and get_proxy_port_udp() functions using process_to_proxy_cache_.
         *
         * @note The function performs direct string matching without regex support. All comparisons
         *       are case-sensitive as input is already converted to uppercase by calling functions.
         */
        bool match_app_name(const std::wstring& app, const std::shared_ptr<iphelper::network_process>& process) const
        {
            if (!process) return false;

            // Exclude the current process by process ID (not cached since it's a quick check)
            if (process->id == ::GetCurrentProcessId())
                return false;

            // Check exclusion list
            for (const auto& excluded_entry : excluded_list_) {
                if ((excluded_entry.find(L'\\') != std::wstring::npos || excluded_entry.find(L'/') != std::wstring::npos)
                    ? (process->path_name.find(excluded_entry) != std::wstring::npos)
                    : (process->name.find(excluded_entry) != std::wstring::npos)
                    ) {
                    process->excluded = true;
                    return false; // Excluded
                }
            }

            return (app.find(L'\\') != std::wstring::npos || app.find(L'/') != std::wstring::npos)
                    ? (process->path_name.find(app) != std::wstring::npos)
                    : (process->name.find(app) != std::wstring::npos);
        }

        /**
         * Retrieves the TCP proxy port number associated with a given process name.
         * @param process The pointer to network_process.
         * @return A std::optional containing the TCP port number if the process name is found,
         *         or an empty std::optional otherwise.
         */
        std::optional<uint16_t> get_proxy_port_tcp(const std::shared_ptr<iphelper::network_process>& process)
        {
            if (!process) return {};

            std::shared_lock lock(lock_);

            for (const auto& [proxy_id, process_pattern] : proxy_to_names_)
            {
                if (match_app_name(process_pattern, process))
                {
                    return proxy_servers_[proxy_id].first
                        ? std::optional(proxy_servers_[proxy_id].first->proxy_port())
                        : std::nullopt;
                }
            }

            return {};
        }

        /**
         * Retrieves the UDP proxy port number associated with a given process name.
         * @param process The pointer to network_process.
         * @return A std::optional containing the UDP port number if the process name is found,
         *         or an empty std::optional otherwise.
         */
        std::optional<uint16_t> get_proxy_port_udp(const std::shared_ptr<iphelper::network_process>& process)
        {
            if (!process) return {};

            std::shared_lock lock(lock_);

            // Search for a matching process pattern
            for (const auto& [proxy_id, process_pattern] : proxy_to_names_)
            {
                if (match_app_name(process_pattern, process))
                {
                    return proxy_servers_[proxy_id].second
                        ? std::optional(proxy_servers_[proxy_id].second->proxy_port())
                        : std::nullopt;
                }
            }

            return {};
        }

        /**
         * Checks if the given TCP port number is being used by any of the current proxy servers.
         * @param port The TCP port number to check.
         * @return True if the port number is used by any proxy server, false otherwise.
         */
        bool is_tcp_proxy_port(const uint16_t port)
        {
            // Locks the proxy servers list for reading.
            std::shared_lock lock(lock_);

            // Checks each proxy server to see if the given port number is being used.
            // Returns true if any server is using the port, false otherwise.
            return std::ranges::any_of(std::as_const(proxy_servers_), [port](auto& proxy)
            {
                if (proxy.first && proxy.first->proxy_port() == port)
                    return true;
                return false;
            });
        }

        /**
         * Checks if the given UDP port number is being used by any of the current proxy servers.
         * @param port The UDP port number to check.
         * @return True if the port number is used by any proxy server, false otherwise.
         */
        bool is_udp_proxy_port(const uint16_t port)
        {
            // Locks the proxy servers list for reading.
            std::shared_lock lock(lock_);

            // Checks each proxy server to see if the given port number is being used.
            // Returns true if any server is using the port, false otherwise.
            return std::ranges::any_of(std::as_const(proxy_servers_), [port](auto& proxy)
            {
                if (proxy.second && proxy.second->proxy_port() == port)
                    return true;
                return false;
            });
        }

        /**
         * @brief Processes a UDP packet for possible redirection through a proxy.
         *
         * This function inspects the provided intermediate_buffer, attempts to resolve the associated process,
         * and determines if the UDP packet should be redirected to a proxy port, passed through, or reverted.
         * If the process cannot be resolved and @p postponed is false, the function returns std::nullopt,
         * indicating that the packet should be queued for later processing. If @p postponed is true, a
         * second attempt is made to resolve the process using an updated process table.
         *
         * If the process is associated with a UDP proxy, and the packet is from a new endpoint, the source
         * port is recorded and a redirection is logged. The function then attempts to process the packet for
         * client-to-server redirection. If the packet is from a known proxy port, it attempts to process it
         * for server-to-client redirection.
         *
         * @param buffer Reference to the intermediate_buffer containing the packet data.
         * @param postponed If false, only the current process table is used for lookup. If true, the process
         *        table is refreshed and a second lookup is attempted.
         * @return std::optional<packet_filter::packet_action> indicating the action to take:
         *         - std::nullopt: process could not be resolved (should be queued for later)
         *         - packet_action::revert: packet should be reverted (redirected)
         *         - packet_action::pass: packet should be passed through
         */
        std::optional<packet_filter::packet_action> process_udp_packet(ndisapi::intermediate_buffer& buffer, const bool postponed)
        {
            auto* const ethernet_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);
            auto* const ip_header = reinterpret_cast<iphdr_ptr>(ethernet_header + 1);
            auto* const udp_header = reinterpret_cast<udphdr_ptr>(reinterpret_cast<PUCHAR>(ip_header)
                + sizeof(DWORD) * ip_header->ip_hl);
            const auto* const dns_payload = reinterpret_cast<const uint8_t*>(udp_header + 1);
            const auto udp_payload_size = ntohs(udp_header->length) >= sizeof(udphdr)
                ? static_cast<size_t>(ntohs(udp_header->length) - sizeof(udphdr))
                : 0U;

            // If the packet is from a known proxy port, process for server-to-client redirection
            if (is_udp_proxy_port(ntohs(udp_header->th_sport)))
            {
                if (udp_redirect_->process_server_to_client_packet(buffer))
                {
                    log_packet_to_pcap(buffer);
                    return packet_filter::packet_action{ packet_filter::packet_action::action_type::revert };
                }
            }

            if (ntohs(udp_header->th_sport) == 53)
            {
                cache_dns_response(ip_header, udp_header, dns_payload, udp_payload_size);
                return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };
            }

            if (ntohs(udp_header->th_dport) == 53)
            {
                auto process = process_lookup_v4_.lookup_process_for_udp<false>(net::ip_endpoint<net::ip_address_v4>{
                    ip_header->ip_src, ntohs(udp_header->th_sport)
                });

                if (!process && postponed)
                {
                    process = process_lookup_v4_.lookup_process_for_udp<true>(net::ip_endpoint<net::ip_address_v4>{
                        ip_header->ip_src, ntohs(udp_header->th_sport)
                    });
                }
                else if (!process)
                {
                    return std::nullopt;
                }

                if (process)
                {
                    if (try_hijack_dns_query(buffer, ip_header, udp_header, process, udp_payload_size))
                    {
                        log_packet_to_pcap(buffer);
                        return packet_filter::packet_action{ packet_filter::packet_action::action_type::revert };
                    }

                    cache_dns_query(
                        ip_header,
                        udp_header,
                        *process,
                        should_allow_shared_dns_lookup(*process),
                        dns_payload,
                        udp_payload_size);
                }
                else if (postponed)
                {
                    return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };
                }

                return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };
            }

            auto process = process_lookup_v4_.
                lookup_process_for_udp<false>(net::ip_endpoint<net::ip_address_v4>{
                ip_header->ip_src, ntohs(udp_header->th_sport)
            });

            if (!process)
            {
                if (postponed)
                {
                    process = process_lookup_v4_.
                        lookup_process_for_udp<true>(net::ip_endpoint<net::ip_address_v4>{
                        ip_header->ip_src, ntohs(udp_header->th_sport)
                    });
                }
                else
                {
                    return std::nullopt;
                }
            }

            if (!process)
                return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };

            if (process->excluded || process->bypass_udp)
                return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };

            if (const auto port = process->udp_proxy_port ? process->udp_proxy_port : get_proxy_port_udp(process); port.has_value())
            {
                if (udp_redirect_->is_new_endpoint(buffer))
                {
                    std::scoped_lock lock(udp_mapper_lock_);
                    udp_mapper_.insert(ntohs(udp_header->th_sport));

                    NETLIB_LOG(log_level::info,
                        "Redirecting UDP {} : {} -> {} : {}",
                        net::ip_address_v4(ip_header->ip_src), ntohs(udp_header->th_sport),
                        net::ip_address_v4(ip_header->ip_dst), ntohs(udp_header->th_dport));
                }

                if (udp_redirect_->process_client_to_server_packet(buffer, htons(port.value())))
                {
                    log_packet_to_pcap(buffer);
                    return packet_filter::packet_action{ packet_filter::packet_action::action_type::revert };
                }

            }
            else
            {
                process->bypass_udp = true;
            }

            return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };
        }

        std::optional<packet_filter::packet_action> process_udp_packet_v6(ndisapi::intermediate_buffer& buffer, const bool postponed)
        {
            auto* const ethernet_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);
            auto* const ip_header = reinterpret_cast<ipv6hdr_ptr>(ethernet_header + 1);
            auto [transport_header, protocol] = net::ipv6_helper::find_transport_header(
                ip_header,
                buffer.m_Length - ETHER_HEADER_LENGTH);

            if (transport_header == nullptr || protocol != IPPROTO_UDP)
            {
                return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };
            }

            auto* const udp_header = static_cast<udphdr_ptr>(transport_header);
            const auto* const dns_payload = reinterpret_cast<const uint8_t*>(udp_header + 1);
            const auto udp_payload_size = ntohs(udp_header->length) >= sizeof(udphdr)
                ? static_cast<size_t>(ntohs(udp_header->length) - sizeof(udphdr))
                : 0U;

            if (ntohs(udp_header->th_sport) == 53)
            {
                return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };
            }

            if (ntohs(udp_header->th_dport) == 53)
            {
                auto process = process_lookup_v6_.lookup_process_for_udp<false>(net::ip_endpoint<net::ip_address_v6>{
                    ip_header->ip6_src, ntohs(udp_header->th_sport)
                });

                if (!process && postponed)
                {
                    process = process_lookup_v6_.lookup_process_for_udp<true>(net::ip_endpoint<net::ip_address_v6>{
                        ip_header->ip6_src, ntohs(udp_header->th_sport)
                    });
                }
                else if (!process)
                {
                    return std::nullopt;
                }

                if (process)
                {
                    if (try_hijack_dns_query_ipv6(buffer, ip_header, udp_header, process, udp_payload_size))
                    {
                        log_packet_to_pcap(buffer);
                        return packet_filter::packet_action{ packet_filter::packet_action::action_type::revert };
                    }
                }
                else if (postponed)
                {
                    return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };
                }
            }

            return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };
        }

        /**
         * @brief Processes a TCP packet for possible redirection through a proxy.
         *
         * This function inspects the provided intermediate_buffer, attempts to resolve the associated process,
         * and determines if the TCP packet should be redirected to a proxy port, passed through, or reverted.
         * If the process cannot be resolved and @p postponed is false, the function returns std::nullopt,
         * indicating that the packet should be queued for later processing. If @p postponed is true, a
         * second attempt is made to resolve the process using an updated process table.
         *
         * If the process is associated with a TCP proxy, and the packet is a SYN (connection initiation),
         * the source port is mapped to the destination endpoint and a redirection is logged. The function
         * then attempts to process the packet for client-to-server redirection. If the packet is from a
         * known proxy port, it attempts to process it for server-to-client redirection.
         *
         * @param buffer Reference to the intermediate_buffer containing the packet data.
         * @param postponed If false, only the current process table is used for lookup. If true, the process
         *        table is refreshed and a second lookup is attempted.
         * @return std::optional<packet_filter::packet_action> indicating the action to take:
         *         - std::nullopt: process could not be resolved (should be queued for later)
         *         - packet_action::revert: packet should be reverted (redirected)
         *         - packet_action::pass: packet should be passed through
         */
        std::optional<packet_filter::packet_action> process_tcp_packet(ndisapi::intermediate_buffer& buffer, const bool postponed)
        {
            auto* const ethernet_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);
            auto* const ip_header = reinterpret_cast<iphdr_ptr>(ethernet_header + 1);
            const auto* const tcp_header = reinterpret_cast<tcphdr_ptr>(reinterpret_cast<PUCHAR>(
                ip_header) +
                sizeof(DWORD) * ip_header->ip_hl);

            // If the packet is from a known proxy port, process for server-to-client redirection
            if (is_tcp_proxy_port(ntohs(tcp_header->th_sport)))
            {
                if (tcp_redirect_->process_server_to_client_packet(buffer))
                {
                    log_packet_to_pcap(buffer);
                    return packet_filter::packet_action{ packet_filter::packet_action::action_type::revert };
                }
            }

            auto process = process_lookup_v4_.
                lookup_process_for_tcp<false>(net::ip_session<net::ip_address_v4>{
                ip_header->ip_src, ip_header->ip_dst, ntohs(tcp_header->th_sport),
                    ntohs(tcp_header->th_dport)
            });

            if (!process)
            {
                if (postponed)
                {
                    process = process_lookup_v4_.
                        lookup_process_for_tcp<true>(net::ip_session<net::ip_address_v4>{
                        ip_header->ip_src, ip_header->ip_dst, ntohs(tcp_header->th_sport),
                            ntohs(tcp_header->th_dport)
                    });
                }
                else
                {
                    return std::nullopt;
                }
            }

            if (!process)
                return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };

            if (process->excluded || process->bypass_tcp)
                return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };

            if (const auto port = process->tcp_proxy_port ? process->tcp_proxy_port : get_proxy_port_tcp(process); port.has_value())
            {
                // If this is a SYN packet (connection initiation), map the source port to the destination endpoint
                if ((tcp_header->th_flags & (TH_SYN | TH_ACK)) == TH_SYN)
                {
                    auto destination_info = tcp_destination_info{
                        net::ip_endpoint(net::ip_address_v4(ip_header->ip_dst), ntohs(tcp_header->th_dport)),
                        lookup_dns_hostname(*process, net::ip_address_v4(ip_header->ip_dst))
                    };

                    std::scoped_lock lock(tcp_mapper_lock_);
                    tcp_mapper_[ntohs(tcp_header->th_sport)] = destination_info;

                    if (destination_info.hostname)
                    {
                        NETLIB_LOG(log_level::info,
                            "Redirecting TCP: {} : {} -> {} : {} ({})",
                            net::ip_address_v4(ip_header->ip_src), ntohs(tcp_header->th_sport),
                            net::ip_address_v4(ip_header->ip_dst), ntohs(tcp_header->th_dport),
                            destination_info.hostname.value());
                    }
                    else
                    {
                        NETLIB_LOG(log_level::info,
                            "Redirecting TCP: {} : {} -> {} : {}",
                            net::ip_address_v4(ip_header->ip_src), ntohs(tcp_header->th_sport),
                            net::ip_address_v4(ip_header->ip_dst), ntohs(tcp_header->th_dport));
                    }
                }

                // Attempt to process the packet for client-to-server redirection
                if (tcp_redirect_->process_client_to_server_packet(buffer, htons(port.value())))
                {
                    log_packet_to_pcap(buffer);
                    return packet_filter::packet_action{ packet_filter::packet_action::action_type::revert };
                }
            }
            else
            {
                process->bypass_tcp = true;
            }

            // Otherwise, pass the packet through
            return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };
        }

        /**
         * @brief Logs a single packet to the pcap logger.
         *
         * This function logs a single packet to the pcap logger if it is available.
         *
         * @param packet The packet to be logged.
         */
        void log_packet_to_pcap(const INTERMEDIATE_BUFFER& packet) {
            if (pcap_logger_) {
                pcap_logger_.value() << packet;
            }
        }

        /**
         * @brief Sends a queue of packets to the network adapters.
         *
         * This method takes a vector of intermediate_buffer pointers and sends them to the network adapters
         * using the underlying packet filter. The packets are sent unsorted, and the number of successfully
         * sent packets is tracked internally.
         *
         * @param packet_queue Reference to a vector of intermediate_buffer pointers to be sent.
         * @return true if the packets were successfully sent to the adapters, false otherwise.
         */
        bool send_packets_to_adapters(std::vector<ndisapi::intermediate_buffer_pool::intermediate_buffer_ptr>& packet_queue) const
        {
            DWORD packets_success = 0;
            return packet_filter_->SendPacketsToAdaptersUnsorted(
                reinterpret_cast<PINTERMEDIATE_BUFFER*>(packet_queue.data()),
                static_cast<DWORD>(packet_queue.size()),
                &packets_success
            );
        }

        /**
         * @brief Sends a queue of packets to the Microsoft TCP/IP stack (MSTCP).
         *
         * This method takes a vector of intermediate_buffer pointers and sends them to the MSTCP stack
         * using the underlying packet filter. The packets are sent unsorted, and the number of successfully
         * sent packets is tracked internally.
         *
         * @param packet_queue Reference to a vector of intermediate_buffer pointers to be sent.
         * @return true if the packets were successfully sent to MSTCP, false otherwise.
         */
        bool send_packets_to_mstcp(std::vector<ndisapi::intermediate_buffer_pool::intermediate_buffer_ptr>& packet_queue) const
        {
            DWORD packets_success = 0;
            return packet_filter_->SendPacketsToMstcpUnsorted(
                reinterpret_cast<PINTERMEDIATE_BUFFER*>(packet_queue.data()),
                static_cast<DWORD>(packet_queue.size()),
                &packets_success
            );
        }

        /**
        * @brief Thread procedure for deferred process resolution and packet forwarding.
        *
        * This method runs in a dedicated thread and is responsible for processing packets
        * that could not be immediately associated with a process. It waits for packets to
        * appear in the process_resolve_buffer_queue_, then attempts to resolve the process
        * information using an updated process table. Based on the result of the resolution
        * and packet inspection, packets are either sent to network adapters, sent to the
        * Microsoft TCP/IP stack, or dropped. The method ensures thread safety and efficient
        * processing by using local queues and minimizing lock contention.
        *
        * The main steps are:
        * 1. Wait for packets to be queued or for the router to become inactive.
        * 2. Swap the shared queue with a local queue for processing.
        * 3. Refresh the process lookup table.
        * 4. For each packet, attempt to resolve the process and determine the appropriate
        *    action (pass to adapter, revert to MSTCP, or assert on unexpected cases).
        * 5. Send processed packets to their respective destinations and clear local queues.
        *
        * The thread exits when the router is deactivated and the queue is empty.
        */
        void process_resolve_thread_proc()
        {
            // Use local (non-static) containers to avoid static initialization order issues and data races
            std::queue<ndisapi::intermediate_buffer_pool::intermediate_buffer_ptr> local_queue;
            std::vector<ndisapi::intermediate_buffer_pool::intermediate_buffer_ptr> to_adapters;
            std::vector<ndisapi::intermediate_buffer_pool::intermediate_buffer_ptr> to_mstcp;

            while (is_active_.load())
            {
                {
                    std::unique_lock lock(process_resolve_buffer_mutex_);
                    process_resolve_buffer_queue_cv_.wait(lock, [this] {
                        return !process_resolve_buffer_queue_.empty() || !is_active_.load();
                        });

                    if (!is_active_.load() && process_resolve_buffer_queue_.empty())
                        break;

                    // Swap the contents of the shared queue with the local queue
                    std::swap(process_resolve_buffer_queue_, local_queue);
                }

                // Actualize process lookup before processing
                process_lookup_v4_.actualize(true, true);
                process_lookup_v6_.actualize(true, true);

                while (!local_queue.empty())
                {
                    auto buffer_ptr = std::move(local_queue.front());
                    local_queue.pop();

                    auto* const ethernet_header = reinterpret_cast<ether_header_ptr>(buffer_ptr->m_IBuffer);
                    const auto ether_type = ntohs(ethernet_header->h_proto);

                    if (ether_type == ETH_P_IP)
                    {
                        if (const auto* const ip_header = reinterpret_cast<iphdr_ptr>(ethernet_header + 1);
                            ip_header->ip_p == IPPROTO_UDP)
                        {
                            if (const auto result = process_udp_packet(*buffer_ptr, true);
                                result && result->action == packet_filter::packet_action::action_type::pass)
                            {
                                to_adapters.push_back(std::move(buffer_ptr));
                            }
                            else if (result && result->action == packet_filter::packet_action::action_type::revert)
                            {
                                to_mstcp.push_back(std::move(buffer_ptr));
                            }
                            else
                            {
                                // Should always have a result for postponed packets
                                assert(false && "process_udp_packet should always return a result for postponed packets");
                            }
                        }
                        else if (ip_header->ip_p == IPPROTO_TCP)
                        {
                            if (const auto result = process_tcp_packet(*buffer_ptr, true);
                                result && result->action == packet_filter::packet_action::action_type::pass)
                            {
                                to_adapters.push_back(std::move(buffer_ptr));
                            }
                            else if (result && result->action == packet_filter::packet_action::action_type::revert)
                            {
                                to_mstcp.push_back(std::move(buffer_ptr));
                            }
                            else
                            {
                                // Should always have a result for postponed packets
                                assert(false && "process_tcp_packet should always return a result for postponed packets");
                            }
                        }
                    }
                    else if (ether_type == ETH_P_IPV6)
                    {
                        if (const auto result = process_udp_packet_v6(*buffer_ptr, true);
                            result && result->action == packet_filter::packet_action::action_type::pass)
                        {
                            to_adapters.push_back(std::move(buffer_ptr));
                        }
                        else if (result && result->action == packet_filter::packet_action::action_type::revert)
                        {
                            to_mstcp.push_back(std::move(buffer_ptr));
                        }
                        else
                        {
                            assert(false && "process_udp_packet_v6 should always return a result for postponed packets");
                        }
                    }
                }

                if (!to_adapters.empty())
                {
                    send_packets_to_adapters(to_adapters);
                    to_adapters.clear();
                }

                if (!to_mstcp.empty())
                {
                    send_packets_to_mstcp(to_mstcp);
                    to_mstcp.clear();
                }
            }
        }

        /**
         * @brief Callback function that is called when the IP interface changes.
         *
         * This function is triggered by changes in the network configuration and
         * updates the network configuration accordingly.
         *
         * @param row Pointer to the MIB_IPINTERFACE_ROW structure that contains
         *            information about the IP interface that changed.
         * @param notification_type The type of notification that triggered the callback.
         */
        void ip_interface_changed_callback([[maybe_unused]] PMIB_IPINTERFACE_ROW row, [[maybe_unused]] MIB_NOTIFICATION_TYPE notification_type)
        {
            NETLIB_LOG(log_level::debug, "Network configuration has changed.");
            update_network_configuration();
        }

        /**
         * @brief Updates the network configuration by filtering or unfiltering network adapters.
         *
         * This function retrieves the list of network adapters and external network connections,
         * determines which adapters need to be filtered, and applies the appropriate filters.
         */
        void update_network_configuration()
        {
            const auto ndis_adapters = packet_filter_->get_interface_list();
            const auto configured_interfaces = iphelper::network_adapter_info::get_external_network_connections();
            std::unordered_set<std::string> adapters_to_filter;

            for (const auto& adapter : configured_interfaces)
            {
                if (adapter.get_if_type() != IF_TYPE_PPP)
                {
                    if (const auto it = std::ranges::find_if(ndis_adapters,
                        [&adapter](const auto& ndis_adapter)
                        {
                            return ndis_adapter.get_internal_name().find(adapter.get_adapter_name()) != std::string::npos;
                        }); it != ndis_adapters.end())
                    {
                        adapters_to_filter.insert(it->get_internal_name());
                    }
                }
                else
                {
                    if (const auto it = std::ranges::find_if(ndis_adapters,
                        [&adapter](const auto& ndis_adapter)
                        {
                            if (const auto wan_info = ndis_adapter.get_ras_links(); wan_info)
                            {
                                return std::any_of(wan_info->begin(), wan_info->end(),
                                    [&adapter](const auto& ras_link)
                                    {
                                        return adapter.has_address(ras_link.ip_address);
                                    });
                            }
                            return false;
                        }); it != ndis_adapters.end())
                    {
                        adapters_to_filter.insert(it->get_internal_name());
                    }
                }
            }

            {
                std::shared_lock lock(adapters_to_filter_lock_);
                if (adapters_to_filter_ == adapters_to_filter)
                    return;
            }

            for (const auto& adapter : ndis_adapters)
            {
                if (const auto& internal_name = adapter.get_internal_name(); adapters_to_filter.contains(internal_name))
                {
                    packet_filter_->filter_network_adapter(internal_name);
                    NETLIB_LOG(log_level::debug, "Filtering network interface: {}", adapter.get_friendly_name());
                }
                else
                {
                    packet_filter_->unfilter_network_adapter(internal_name);
                    NETLIB_LOG(log_level::debug, "Unfiltering network interface: {}", adapter.get_friendly_name());
                }
            }

            {
                std::unique_lock lock(adapters_to_filter_lock_);
                adapters_to_filter_ = std::move(adapters_to_filter);
            }
        }
        
        /**
        * @brief Builds and adds IPv4 pass-through filters for common local network ranges.
        *
        * The function generates inbound and outbound filters that allow traffic
        * for a predefined set of local and special-purpose IPv4 subnets and adds
        * them to the static filters list.
        *
        * Bypassed ranges:
        * - 10.0.0.0/8      (Private Class A)
        * - 172.16.0.0/12   (Private Class B)
        * - 192.168.0.0/16  (Private Class C)
        * - 224.0.0.0/4     (Multicast)
        * - 169.254.0.0/16  (Link-local / APIPA)
        */
        void add_lan_dns_redirect_filters_v4()
        {
            static constexpr std::array<std::pair<const char*, const char*>, 5> local_ranges{ {
                {"10.0.0.0",    "255.0.0.0"},
                {"172.16.0.0",  "255.240.0.0"},
                {"192.168.0.0", "255.255.0.0"},
                {"224.0.0.0",   "240.0.0.0"},
                {"169.254.0.0", "255.255.0.0"}
            } };

            const auto to_subnet = [](const char* address, const char* mask) {
                return net::ip_subnet{
                    net::ip_address_v4{address},
                    net::ip_address_v4{mask}
                };
            };

            const auto add_dns_filters_for_protocol = [this, &to_subnet](const uint8_t protocol) {
                for (const auto& [address, mask] : local_ranges)
                {
                    const auto subnet = to_subnet(address, mask);

                    ndisapi::filter<net::ip_address_v4> in_filter;
                    in_filter
                        .set_protocol(protocol)
                        .set_direction(ndisapi::direction_t::in)
                        .set_action(ndisapi::action_t::redirect)
                        .set_source_address(subnet)
                        .set_source_port(std::make_pair<uint16_t, uint16_t>(53, 53));
                    static_filters_.add_filter_front(in_filter);

                    ndisapi::filter<net::ip_address_v4> out_filter;
                    out_filter
                        .set_protocol(protocol)
                        .set_direction(ndisapi::direction_t::out)
                        .set_action(ndisapi::action_t::redirect)
                        .set_dest_address(subnet)
                        .set_dest_port(std::make_pair<uint16_t, uint16_t>(53, 53));
                    static_filters_.add_filter_front(out_filter);
                }
            };

            add_dns_filters_for_protocol(IPPROTO_UDP);
            add_dns_filters_for_protocol(IPPROTO_TCP);

            NETLIB_LOG(log_level::info,
                "LAN bypass DNS exception enabled - local DNS traffic will still be inspected.");
        }

        void add_lan_passover_filters_v4()
        {
            // List of local IPv4 address ranges (address + subnet mask)
            static constexpr std::array<std::pair<const char*, const char*>, 5> local_ranges{ {
                {"10.0.0.0",    "255.0.0.0"},      // 10.0.0.0/8 - Private Class A
                {"172.16.0.0",  "255.240.0.0"},    // 172.16.0.0/12 - Private Class B
                {"192.168.0.0", "255.255.0.0"},    // 192.168.0.0/16 - Private Class C
                {"224.0.0.0",   "240.0.0.0"},      // 224.0.0.0/4 - Multicast (224.0.0.0 - 239.255.255.255)
                {"169.254.0.0", "255.255.0.0"}     // 169.254.0.0/16 - Link-local (APIPA)
            } };

            // Helper to construct an IPv4 subnet object from string literals
            const auto to_subnet = [](const char* address, const char* mask) {
                return net::ip_subnet{
                    net::ip_address_v4{address},
                    net::ip_address_v4{mask}
                };
                };

            for (const auto& [address, mask] : local_ranges) {
                const auto subnet = to_subnet(address, mask);

                // Allow inbound traffic originating from the local subnet
                ndisapi::filter<net::ip_address_v4> in_filter;
                in_filter
                    .set_direction(ndisapi::direction_t::in)
                    .set_action(ndisapi::action_t::pass)
                    .set_source_address(subnet);
                static_filters_.add_filter_front(in_filter);

                // Allow outbound traffic destined to the local subnet
                ndisapi::filter<net::ip_address_v4> out_filter;
                out_filter
                    .set_direction(ndisapi::direction_t::out)
                    .set_action(ndisapi::action_t::pass)
                    .set_dest_address(subnet);
                static_filters_.add_filter_front(out_filter);
            }

            NETLIB_LOG(log_level::info, "LAN bypass enabled - local network traffic will not be proxied");
        }
    };
}
