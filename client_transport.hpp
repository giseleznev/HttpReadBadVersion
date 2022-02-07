#pragma once

#include <boost/asio/ip/resolver_base.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/ssl.hpp>

namespace elx::http
{
    class client_transport
    {
    public:
        [[nodiscard]] virtual boost::beast::tcp_stream& stream() = 0;

        virtual boost::beast::error_code set_hostname(const std::string& hostname) { return { }; }
        virtual void handshake() { }

        void connect(const boost::beast::tcp_stream::endpoint_type& endpoint)
        {
            stream().connect(endpoint);
        }
    };

    class client_transport_plain :
        public client_transport
    {
    public:
        client_transport_plain(boost::asio::io_context& io_ctx) :
            m_stream(io_ctx)
        {
        }

        [[nodiscard]] boost::beast::tcp_stream& stream() override
        {
            return m_stream;
        }

    private:
        boost::beast::tcp_stream m_stream;
    };

    class client_transport_tls :
        public client_transport
    {
    public:
        client_transport_tls(boost::asio::io_context& io_ctx, boost::asio::ssl::context& ssl_ctx) :
            m_io_ctx(io_ctx),
            m_ssl_ctx(ssl_ctx),
            m_stream(io_ctx, ssl_ctx)
        {
        }

        [[nodiscard]] boost::beast::tcp_stream& stream() override
        {
            return m_stream.next_layer();
        }

        boost::beast::error_code set_hostname(const std::string& hostname) override
        {
            // Set SNI Hostname (many hosts need this to handshake successfully)
            if (not SSL_set_tlsext_host_name(m_stream.native_handle(), hostname.c_str())) {
                return boost::beast::error_code{static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()};
            }

            return { };
        }

        void handshake() override
        {
            m_stream.handshake(boost::asio::ssl::stream_base::client);
        }

    private:
        boost::asio::io_context& m_io_ctx;
        boost::asio::ssl::context& m_ssl_ctx;
        boost::beast::ssl_stream<boost::beast::tcp_stream> m_stream;
    };
}
