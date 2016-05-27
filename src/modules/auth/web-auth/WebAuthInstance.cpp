/*
    Copyright (C) 2014-2015 Islog

    This file is part of Leosac.

    Leosac is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Leosac is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <core/auth/WiegandCard.hpp>
#include <core/auth/AuthSourceBuilder.hpp>
#include <core/auth/Auth.hpp>
#include <core/CoreUtils.hpp>
#include <core/Scheduler.hpp>
#include <exception/ExceptionsTools.hpp>
#include <boost/algorithm/string/join.hpp>
#include "WebAuthInstance.hpp"
#include "tools/log.hpp"

using namespace Leosac::Module::Auth;
using namespace Leosac::Auth;

WebAuthInstance::WebAuthInstance(zmqpp::context &ctx,
        std::string const &auth_ctx_name,
        const std::list<std::string> &auth_sources_names,
        std::string const &auth_target_name,
        std::string const serverURL,
        std::string const security,
        CoreUtilsPtr core_utils) :
        bus_push_(ctx, zmqpp::socket_type::push),
        bus_sub_(ctx, zmqpp::socket_type::sub),
        name_(auth_ctx_name),
        target_name_(auth_target_name),
        serverURL(serverURL),
        security(security),
        core_utils_(core_utils)
{
    bus_push_.connect("inproc://zmq-bus-pull");
    bus_sub_.connect("inproc://zmq-bus-pub");

    bus_sub_.subscribe("KERNEL");

    INFO("Auth instance (" << auth_ctx_name << ") subscribe to " << boost::algorithm::join(auth_sources_names, ", "));
    for (const auto &auth_source : auth_sources_names)
        bus_sub_.subscribe("S_" + auth_source);
}

WebAuthInstance::~WebAuthInstance()
{
    INFO("WebAuthInstance down");
}

void WebAuthInstance::handle_bus_msg()
{
    zmqpp::message msg;
    zmqpp::message auth_result_msg;

    bus_sub_.receive(msg);
    if (handle_kernel_message(msg))
        return;

    auth_result_msg << ("S_" + name_);
    if (handle_auth(&msg))
    {
        auth_result_msg << Leosac::Auth::AccessStatus::GRANTED;
        INFO(name_ << " GRANTED access to target " << target_name_ << " for someone");
    }
    else
    {
        auth_result_msg << Leosac::Auth::AccessStatus::DENIED;
        INFO(name_ << " DENIED access to target " << target_name_ << " for someone");
    }
    bus_push_.send(auth_result_msg);
}

zmqpp::socket &WebAuthInstance::bus_sub()
{
    return bus_sub_;
}

size_t write_callback(char *ptr, size_t size, size_t nmemb, char **userdata) {
    *userdata = ptr;
    return (size_t) size * nmemb;
}

bool sendrequest(std::string sourcename, std::string pin, std::string cardId) {
    CURL *curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_SSL);

    curl = curl_easy_init();


    if (curl) {

        char *result;

        std::string request("sourcename=");
        request=request.append(sourcename)
                .append("&pin=").append(pin)
                .append("&security=").append(security);

        if(cardId!=""){
            request.append("&cardId").append(cardId);
        }

        cout <<request << endl;


        curl_easy_setopt(curl, CURLOPT_POSTFIELDS,request.c_str());
        curl_easy_setopt(curl, CURLOPT_URL, serverURL.c_str());
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);


        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);




        /* Perform the request, res will get the return code */
        res = curl_easy_perform(curl);
        cout << result<<endl;

        /* Check for errors */
        if (res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));

        /* always cleanup */
        curl_easy_cleanup(curl);
        return std::string(result)==sourcename.append("_Granted");
    }

    curl_global_cleanup();
}

bool WebAuthInstance::handle_auth(zmqpp::message *msg) noexcept
{
    std::string sourcename;
    std::string pin;
    std::string cardId;

    sourcename << msg;
    pin << msg;
    cardId << msg;

    return sendrequest(sourcename,pin,cardId);

}

bool WebAuthInstance::handle_kernel_message(const zmqpp::message &msg)
{
    auto cp = msg.copy();
    std::string tmp;
    cp >> tmp;

    if (tmp == "KERNEL")
    {
        cp >> tmp;
        if (tmp == "SIGHUP")
        {
            reload_auth_config();
        }
        return true;
    }
    return false;
}
