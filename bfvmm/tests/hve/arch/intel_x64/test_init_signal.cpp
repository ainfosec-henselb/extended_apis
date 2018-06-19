//
// Bareflank Extended APIs
//
// Copyright (C) 2018 Assured Information Security, Inc.
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

#include <intrinsics.h>

#include <support/arch/intel_x64/test_support.h>
#include <hve/arch/intel_x64/init_signal.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

bool test_handler(gsl::not_null<vmcs_t *>)
{
    return true;
}

namespace eapis
{
namespace intel_x64
{

TEST_CASE("init_signal::init_signal")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);

    CHECK_NOTHROW(eapis::intel_x64::init_signal(hve.get()));
}

TEST_CASE("init_signal::add_handler")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto init_signal = eapis::intel_x64::init_signal(hve.get());
    auto hdlr = init_signal::handler_delegate_t::create<test_handler>();

    CHECK_NOTHROW(init_signal.add_handler(std::move(hdlr)));
}

TEST_CASE("init_signal::handle")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto ehlr = hve->exit_handler();

    namespace reason = vmcs_n::exit_reason::basic_exit_reason;

    auto init_signal = eapis::intel_x64::init_signal(hve.get());
    auto hdlr = init_signal::handler_delegate_t::create<test_handler>();
    init_signal.add_handler(std::move(hdlr));
    g_vmcs_fields[vmcs_n::exit_reason::addr] = reason::init_signal;

    CHECK_NOTHROW(ehlr->handle(ehlr));
}

}
}

#endif