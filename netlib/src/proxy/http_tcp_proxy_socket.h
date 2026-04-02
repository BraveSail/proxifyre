#pragma once

namespace proxy
{
    /**
     * @class http_tcp_proxy_socket
     * @brief Implements an HTTP CONNECT TCP proxy socket with optional Basic authentication.
     *
     * This class extends tcp_proxy_socket to provide HTTP CONNECT tunnel support.
     * It manages the HTTP CONNECT handshake and transitions to data relay once
     * the tunnel is established.
     *
     * @tparam T Address type (e.g., IPv4 or IPv6).
     */
    template <net::ip_address T>
    class http_tcp_proxy_socket final : public tcp_proxy_socket<T>  // NOLINT(clang-diagnostic-padded)
    {
        /**
         * @enum http_state
         * @brief Internal state machine for HTTP CONNECT negotiation.
         */
        enum class http_state : uint8_t
        {
            pre_connect,
            connect_sent
        };

    public:
        using log_level = netlib::log::log_level;
        using address_type_t = T;
        using negotiate_context_t = http_negotiate_context<T>;
        using per_io_context_t = tcp_per_io_context<T>;

        /**
         * @brief Constructs an HTTP CONNECT TCP proxy socket.
         */
        http_tcp_proxy_socket(const SOCKET local_socket, const SOCKET remote_socket,
            std::unique_ptr<negotiate_context_t> negotiate_ctx,
            const log_level log_level = log_level::error,
            std::shared_ptr<std::ostream> log_stream = nullptr)
            : tcp_proxy_socket<T>(local_socket, remote_socket, std::move(negotiate_ctx), log_level,
                std::move(log_stream))
        {
        }

        /**
         * @brief Initializes the per-I/O contexts with shared_ptr to this socket.
         */
        void initialize_io_contexts() override
        {
            tcp_proxy_socket<T>::initialize_io_contexts();

            auto base_ptr = this->shared_from_this();
            auto self = std::dynamic_pointer_cast<http_tcp_proxy_socket>(base_ptr);

            if (!self)
            {
                NETLIB_ERROR("initialize_io_contexts: dynamic_pointer_cast to http_tcp_proxy_socket failed");
                throw std::runtime_error(
                    "http_tcp_proxy_socket::initialize_io_contexts(): dynamic_pointer_cast failed.");
            }

            io_context_recv_negotiate_.proxy_socket_ptr = self;
            io_context_send_negotiate_.proxy_socket_ptr = self;

            NETLIB_DEBUG("initialize_io_contexts: HTTP CONNECT negotiation contexts initialized successfully");
        }

        /**
         * @brief Handles completion of an HTTP CONNECT negotiation receive operation.
         *
         * Accumulates received data and checks for complete HTTP response (terminated by \r\n\r\n).
         * If the response indicates success (HTTP/1.x 200), starts data relay.
         */
        void process_receive_negotiate_complete(const uint32_t io_size, per_io_context_t* io_context) override
        {
            if (io_context->is_local == false && current_state_ == http_state::connect_sent)
            {
                response_received_ += io_size;

                // Check if we have a complete HTTP response (ends with \r\n\r\n)
                if (response_received_ >= 4)
                {
                    std::string_view response(response_buffer_.data(), response_received_);
                    const auto end_pos = response.find("\r\n\r\n");

                    if (end_pos != std::string_view::npos)
                    {
                        // Parse status line: "HTTP/1.x 200 ..."
                        if (response.size() >= 12 &&
                            (response.substr(0, 7) == "HTTP/1." ) &&
                            response.substr(9, 3) == "200")
                        {
                            NETLIB_INFO("HTTP CONNECT tunnel established successfully");
                            tcp_proxy_socket<T>::start_data_relay();
                            return;
                        }

                        // Non-200 response - tunnel failed
                        NETLIB_ERROR("HTTP CONNECT failed: {}", 
                            std::string(response.substr(0, response.find("\r\n"))));
                        tcp_proxy_socket<T>::close_client(true, false);
                        return;
                    }
                }

                // Response not complete yet, continue receiving
                if (response_received_ >= response_buffer_.size())
                {
                    // Response too large - something is wrong
                    NETLIB_ERROR("HTTP CONNECT response exceeded buffer size");
                    tcp_proxy_socket<T>::close_client(true, false);
                    return;
                }

                // Issue another receive for remaining data
                io_context_recv_negotiate_.wsa_buf.buf = response_buffer_.data() + response_received_;
                io_context_recv_negotiate_.wsa_buf.len = static_cast<ULONG>(response_buffer_.size() - response_received_);

                DWORD flags = 0;

                if ((::WSARecv(
                    tcp_proxy_socket<T>::remote_socket_,
                    &io_context_recv_negotiate_.wsa_buf,
                    1,
                    nullptr,
                    &flags,
                    &io_context_recv_negotiate_,
                    nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
                {
                    tcp_proxy_socket<T>::close_client(true, false);
                }
            }
        }

    private:
        per_io_context_t io_context_recv_negotiate_{ proxy_io_operation::negotiate_io_read, nullptr, false };
        per_io_context_t io_context_send_negotiate_{ proxy_io_operation::negotiate_io_write, nullptr, false };

        http_state current_state_{ http_state::pre_connect };
        std::string connect_request_str_;
        std::array<char, 4096> response_buffer_{};
        size_t response_received_{ 0 };

        /**
         * @brief Base64 encoding for Proxy-Authorization header.
         */
        static std::string base64_encode(const std::string& input)
        {
            static constexpr char table[] =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

            std::string encoded;
            encoded.reserve(((input.size() + 2) / 3) * 4);

            uint32_t val = 0;
            int bits = -6;

            for (const uint8_t c : input)
            {
                val = (val << 8) + c;
                bits += 8;
                while (bits >= 0)
                {
                    encoded.push_back(table[(val >> bits) & 0x3F]);
                    bits -= 6;
                }
            }

            if (bits > -6)
                encoded.push_back(table[((val << 8) >> (bits + 8)) & 0x3F]);

            while (encoded.size() % 4)
                encoded.push_back('=');

            return encoded;
        }

    protected:
        /**
         * @brief No local-side negotiation required for HTTP CONNECT.
         */
        bool local_negotiate() override
        {
            return true;
        }

        /**
         * @brief Initiates the HTTP CONNECT negotiation with the remote proxy.
         *
         * Builds and sends the HTTP CONNECT request. If credentials are provided,
         * includes a Proxy-Authorization: Basic header.
         *
         * @return False (negotiation is async), true if not needed.
         */
        bool remote_negotiate() override
        {
            if (tcp_proxy_socket<T>::negotiate_ctx_)
            {
                if (current_state_ == http_state::pre_connect)
                {
                    NETLIB_DEBUG("Starting HTTP CONNECT negotiation with remote proxy");

                    auto* negotiate_context_ptr = dynamic_cast<negotiate_context_t*>(
                        tcp_proxy_socket<T>::negotiate_ctx_.get());

                    // Build target address string from the negotiate context
                    const auto& remote_addr = negotiate_context_ptr->remote_address;
                    const auto remote_port = negotiate_context_ptr->remote_port;
                    const std::string target = std::string(remote_addr) + ":" + std::to_string(remote_port);

                    // Build HTTP CONNECT request
                    connect_request_str_ = "CONNECT " + target + " HTTP/1.1\r\n"
                        "Host: " + target + "\r\n";

                    // Add Proxy-Authorization if credentials are provided
                    if (negotiate_context_ptr->username.has_value() &&
                        negotiate_context_ptr->password.has_value() &&
                        !negotiate_context_ptr->username.value().empty())
                    {
                        const std::string credentials = negotiate_context_ptr->username.value() + ":" +
                            negotiate_context_ptr->password.value();
                        connect_request_str_ += "Proxy-Authorization: Basic " +
                            base64_encode(credentials) + "\r\n";
                        NETLIB_DEBUG("HTTP CONNECT with Proxy-Authorization header");
                    }

                    connect_request_str_ += "\r\n";

                    io_context_send_negotiate_.wsa_buf.buf = connect_request_str_.data();
                    io_context_send_negotiate_.wsa_buf.len = static_cast<ULONG>(connect_request_str_.size());
                    io_context_recv_negotiate_.wsa_buf.buf = response_buffer_.data();
                    io_context_recv_negotiate_.wsa_buf.len = static_cast<ULONG>(response_buffer_.size());

                    DWORD flags = 0;

                    NETLIB_DEBUG("Sending HTTP CONNECT request ({} bytes): CONNECT {}", 
                        connect_request_str_.size(), target);

                    if ((::WSASend(
                        tcp_proxy_socket<T>::remote_socket_,
                        &io_context_send_negotiate_.wsa_buf,
                        1,
                        nullptr,
                        0,
                        &io_context_send_negotiate_,
                        nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
                    {
                        const auto error = WSAGetLastError();
                        NETLIB_ERROR("Failed to send HTTP CONNECT request: WSA error {}", error);
                        tcp_proxy_socket<T>::close_client(false, false);
                        return false;
                    }

                    current_state_ = http_state::connect_sent;
                    NETLIB_DEBUG("HTTP CONNECT request sent, waiting for response");

                    if ((::WSARecv(
                        tcp_proxy_socket<T>::remote_socket_,
                        &io_context_recv_negotiate_.wsa_buf,
                        1,
                        nullptr,
                        &flags,
                        &io_context_recv_negotiate_,
                        nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
                    {
                        const auto error = WSAGetLastError();
                        NETLIB_ERROR("Failed to receive HTTP CONNECT response: WSA error {}", error);
                        tcp_proxy_socket<T>::close_client(true, false);
                        return false;
                    }
                }

                return false;
            }

            NETLIB_DEBUG("HTTP CONNECT negotiation skipped - no negotiation context available");
            return true;
        }
    };
}
