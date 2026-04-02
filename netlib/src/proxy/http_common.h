#pragma once

namespace proxy
{
    /**
     * @brief Context for HTTP CONNECT proxy negotiation, optionally including authentication credentials.
     *
     * Inherits from `negotiate_context<T>`, holding remote address/port.
     *
     * @tparam T Address type (e.g., IPv4, IPv6 struct)
     */
    template <typename T>
    struct http_negotiate_context final : negotiate_context<T>
    {
        /**
         * @brief Constructor for anonymous HTTP CONNECT negotiation (no auth).
         */
        http_negotiate_context(const T& remote_address, uint16_t remote_port)
            : negotiate_context<T>(remote_address, remote_port)
        {
        }

        /**
         * @brief Constructor for negotiation with optional auth parameters.
         */
        http_negotiate_context(const T& remote_srv_address, uint16_t remote_srv_port,
            std::optional<std::string> username, std::optional<std::string> password)
            : negotiate_context<T>(remote_srv_address, remote_srv_port),
            username(std::move(username)),
            password(std::move(password))
        {
        }

        /**
         * @brief Constructor for negotiation with optional auth parameters and destination hostname.
         */
        http_negotiate_context(const T& remote_srv_address, uint16_t remote_srv_port,
            std::optional<std::string> username, std::optional<std::string> password,
            std::optional<std::string> destination_hostname)
            : negotiate_context<T>(remote_srv_address, remote_srv_port),
            username(std::move(username)),
            password(std::move(password)),
            destination_hostname(std::move(destination_hostname))
        {
        }

        /**
         * @brief Constructor for negotiation with mandatory username/password.
         */
        http_negotiate_context(const T& remote_address, uint16_t remote_port,
            std::string username, std::string password)
            : negotiate_context<T>(remote_address, remote_port),
            username(std::move(username)),
            password(std::move(password))
        {
        }

        std::optional<std::string> username{ std::nullopt }; ///< Optional username
        std::optional<std::string> password{ std::nullopt }; ///< Optional password
        std::optional<std::string> destination_hostname{ std::nullopt }; ///< Optional hostname for remote DNS resolution
    };
}
