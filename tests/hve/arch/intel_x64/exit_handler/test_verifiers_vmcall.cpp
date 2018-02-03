//
// Bareflank Extended APIs
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn   <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include "../../../../../include/support/arch/intel_x64/test_support.h"

using namespace x64;
namespace intel = intel_x64;
namespace vmcs = intel_x64::vmcs;

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("exit_handler_intel_x64_eapis_verifiers: json clear denials allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "clear_denials"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;
    ehlr->m_denials.emplace_back("fake denial");

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("exit_handler_intel_x64_eapis_verifiers: json clear denials logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "clear_denials"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;
    ehlr->m_denials.emplace_back("fake denial");

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("exit_handler_intel_x64_eapis_verifiers: json clear denials denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "clear_denials"}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;
    ehlr->m_denials.emplace_back("fake denial");

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("exit_handler_intel_x64_eapis_verifiers: json dump policy allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "dump_policy"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
}

TEST_CASE("exit_handler_intel_x64_eapis_verifiers: json dump policy logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "dump_policy"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
}

TEST_CASE("exit_handler_intel_x64_eapis_verifiers: json dump policy denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "dump_policy"}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
}

TEST_CASE("exit_handler_intel_x64_eapis_verifiers: json dump denials allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "dump_denials"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;
    ehlr->m_denials.emplace_back("fake denial");

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "[\"fake denial\"]");
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("exit_handler_intel_x64_eapis_verifiers: json dump denials logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "dump_denials"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;
    ehlr->m_denials.emplace_back("fake denial");

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ehlr->m_denials.size() == 2);
}

TEST_CASE("exit_handler_intel_x64_eapis_verifiers: json dump denials denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "dump_denials"}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;
    ehlr->m_denials.emplace_back("fake denial");

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() != "[\"fake denial\"]");
    CHECK(ehlr->m_denials.size() == 1);
}

#endif
