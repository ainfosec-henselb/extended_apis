//
// Bareflank Extended APIs
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

#include <bfdebug.h>
#include <hve/arch/intel_x64/hve.h>

namespace eapis
{
namespace intel_x64
{

wrmsr::wrmsr(gsl::not_null<eapis::intel_x64::hve *> hve) :
    m_msr_bitmap{hve->msr_bitmap()},
    m_exit_handler{hve->exit_handler()}
{
    using namespace vmcs_n;

    m_exit_handler->add_handler(
        exit_reason::basic_exit_reason::wrmsr,
        ::handler_delegate_t::create<wrmsr, &wrmsr::handle>(this)
    );
}

wrmsr::~wrmsr()
{
    if (!ndebug && m_log_enabled) {
        dump_log();
    }
}

// -----------------------------------------------------------------------------
// RDMSR
// -----------------------------------------------------------------------------

void
wrmsr::add_handler(
    vmcs_n::value_type msr, handler_delegate_t &&d)
{
#ifndef DISABLE_AUTO_TRAP_ON_ACCESS
    this->trap_on_access(msr);
#endif
    m_handlers[msr].push_front(std::move(d));
}

void
wrmsr::trap_on_access(vmcs_n::value_type msr)
{
    if (msr <= 0x00001FFFUL) {
        return set_bit(m_msr_bitmap, (msr - 0x00000000UL) + 0x4000);
    }

    if (msr >= 0xC0000000UL && msr <= 0xC0001FFFUL) {
        return set_bit(m_msr_bitmap, (msr - 0xC0000000UL) + 0x6000);
    }

    throw std::runtime_error("invalid msr: " + std::to_string(msr));
}

void
wrmsr::trap_on_all_accesses()
{ gsl::memset(m_msr_bitmap.subspan(2048, m_msr_bitmap.size() >> 1), 0xFF); }

void
wrmsr::pass_through_access(vmcs_n::value_type msr)
{
    if (msr <= 0x00001FFFUL) {
        return clear_bit(m_msr_bitmap, (msr - 0x00000000UL) + 0x4000);
    }

    if (msr >= 0xC0000000UL && msr <= 0xC0001FFFUL) {
        return clear_bit(m_msr_bitmap, (msr - 0xC0000000UL) + 0x6000);
    }

    throw std::runtime_error("invalid msr: " + std::to_string(msr));
}

void
wrmsr::pass_through_all_accesses()
{ gsl::memset(m_msr_bitmap.subspan(2048, m_msr_bitmap.size() >> 1), 0x00); }

// -----------------------------------------------------------------------------
// Debug
// -----------------------------------------------------------------------------

void
wrmsr::dump_log()
{
    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_lnbr(0, msg);
        bfdebug_info(0, "wrmsr log", msg);
        bfdebug_brk2(0, msg);

        for (const auto &record : m_log) {
            bfdebug_info(0, "record", msg);
            bfdebug_subnhex(0, "msr", record.msr, msg);
            bfdebug_subnhex(0, "val", record.val, msg);
        }

        bfdebug_lnbr(0, msg);
    });
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
wrmsr::handle(gsl::not_null<vmcs_t *> vmcs)
{

// TODO: IMPORTANT!!!
//
// We need to create a list of MSRs that are implemented and GP when the
// MSR is not implemented. We also need to test to make sure the the hardware
// is enforcing the privilege level of this instruction while the hypervisor
// is loaded.
//
// To fire a GP, we need to add a Bareflank specific exception that can be
// thrown. The base hypervisor can then trap on this type of exception and
// have delegates that can be registered to handle the exeption type, which in
// this case would be the interrupt code that would then inject a GP.
//

    const auto &hdlrs =
        m_handlers.find(
            vmcs->save_state()->rcx
        );

    if (GSL_LIKELY(hdlrs != m_handlers.end())) {

        struct info_t info = {
            vmcs->save_state()->rcx,
            0,
            false,
            false
        };

        info.val =
            ((vmcs->save_state()->rax & 0x00000000FFFFFFFF) << 0) |
            ((vmcs->save_state()->rdx & 0x00000000FFFFFFFF) << 32);

        if (!ndebug && m_log_enabled) {
            add_record(m_log, {
                info.msr, info.val
            });
        }

        for (const auto &d : hdlrs->second) {
            if (d(vmcs, info)) {

                if (!info.ignore_write) {
                    emulate_wrmsr(
                        gsl::narrow_cast<::x64::msrs::field_type>(info.msr),
                        info.val
                    );
                }

                if (!info.ignore_advance) {
                    return advance(vmcs);
                }

                return true;
            }
        }
    }

#ifndef SECURE_MODE
    return false;
#endif

    return advance(vmcs);
}

}
}
