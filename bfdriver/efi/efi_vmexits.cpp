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

#include <bfvmm/vcpu/vcpu_factory.h>
#include <bfvmm/debug/serial/serial_ns16550a.h>
#include <eapis/vcpu/arch/intel_x64/vcpu.h>
#include <eapis/hve/arch/intel_x64/ept/memory_map.h>
#include <eapis/hve/arch/intel_x64/ept/helpers.h>

using namespace eapis::intel_x64;

namespace efi
{

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

static bool
handle_cpuid(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs)
{
    if (vmcs->save_state()->rax == 0xBF01) {
        bfdebug_info(0, "host os is" bfcolor_green " now " bfcolor_end "in a vm");
        return advance(vmcs);
    }

    if (vmcs->save_state()->rax == 0xBF00) {
        bfdebug_info(0, "host os is" bfcolor_red " not " bfcolor_end "in a vm");
        return advance(vmcs);
    }

    auto leaf = vmcs->save_state()->rax;
    //if (thread_context_cpuid() == 1) bfdebug_nhex(0,"cpuid",leaf);
    auto ret =
        ::x64::cpuid::get(
            gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rax),
            gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rbx),
            gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rcx),
            gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rdx)
        );

    vmcs->save_state()->rax = ret.rax;
    vmcs->save_state()->rbx = ret.rbx;
    vmcs->save_state()->rdx = ret.rdx;
    if (leaf == 0x00000001)
    {
        vmcs->save_state()->rcx = (ret.rcx)&(~(1UL<<26))&(~(1UL<<27))&(~(1UL<<5));
        vmcs->save_state()->rdx = (ret.rdx)&(~(1UL<<12));
    }
    else if ((leaf & 0xC0000000) == 0xC0000000)
    {
        // bfdebug_info(0, "leaf & 0xC0000000");
        vmcs->save_state()->rax = 0;
        vmcs->save_state()->rcx = 0;
        vmcs->save_state()->rdx = 0;
    }
    else if (leaf == 0x0000000A)
    {
        vmcs->save_state()->rax = 0;
        vmcs->save_state()->rcx = 0;
    }
    else
    {
        vmcs->save_state()->rcx = ret.rcx;
    }

    return advance(vmcs);
}

static bool
handle_rdmsr(gsl::not_null<vmcs_t *> vmcs)
{
    //if (::intel_x64::vmcs::secondary_processor_based_vm_execution_controls::unrestricted_guest::is_enabled())
    auto msr = gsl::narrow_cast<::x64::msrs::field_type>(vmcs->save_state()->rcx);
    //if (thread_context_cpuid() == 1) bferror_nhex(0, "rdmsr", msr);

    switch (msr) {
        case 0x613:
        case 0x619:
            vmcs->save_state()->rax = 0;
            vmcs->save_state()->rdx = 0;
            return advance(vmcs);
    }

    return false;
}

static bool
handle_wrmsr(gsl::not_null<vmcs_t *> vmcs)
{
    auto msr = gsl::narrow_cast<::x64::msrs::field_type>(vmcs->save_state()->rcx);
    uint64_t val = ((vmcs->save_state()->rdx)<<0x20)|((vmcs->save_state()->rax)&0xFFFFFFFF);
    //if (thread_context_cpuid() == 1) bferror_nhex(0, "wrmsr", msr);
    //if (thread_context_cpuid() == 1) bferror_nhex(0, "wrmsr val", val);
    if (::intel_x64::vmcs::secondary_processor_based_vm_execution_controls::unrestricted_guest::is_enabled())
    {
        bferror_subnhex(0, "rip", ::intel_x64::vmcs::guest_rip::get());
        if (msr != 0xC0000080)
            return false;

        if (val & 1<<8)
        {
            val |= 1<<10;
            ::intel_x64::vmcs::guest_cr0::set((0x60000030ULL)|(1ULL<<0)|(1ULL<<31)|(1ULL<<16));
            ::intel_x64::vmcs::vm_entry_controls::ia_32e_mode_guest::enable();
            ::intel_x64::vmcs::secondary_processor_based_vm_execution_controls::unrestricted_guest::disable();
            ::intel_x64::vmcs::secondary_processor_based_vm_execution_controls::enable_ept::disable();
             ::intel_x64::vmcs::primary_processor_based_vm_execution_controls::monitor_trap_flag::disable();
            // ::intel_x64::vmcs::cr4_guest_host_mask::set(0x2000ULL);
            // ::intel_x64::vmcs::cr0_guest_host_mask::set(0ULL);
        }

        switch (msr) {
            case 0xC0000080:
                ::intel_x64::vmcs::guest_ia32_efer::set(val);
                return advance(vmcs);
        }
    }

    return false;
}


static bool
handle_vmx_preemption_timer_expired(gsl::not_null<vmcs_t *> vmcs)
{
    //bfdebug_info(0,"pulse");
    char p = 'n';
    if (thread_context_cpuid() == 0)
        p = '0';
    else if (thread_context_cpuid() == 1)
        p = '1';
    bfvmm::serial_ns16550a serial;
    serial.write(p);
    serial.write('\n');

    return true;
}

static bool
handle_ept_misconfiguration(gsl::not_null<vmcs_t *> vmcs)
{
    ::intel_x64::vmcs::debug::dump();
    auto ret = ::x64::cpuid::get(0x80000008,0,0,0);
    bferror_subnhex(0, "width", ret.rax);
    uint64_t eptp = ::intel_x64::vmcs::ept_pointer::get();
    bferror_subnhex(0, "eptp", eptp);
    uint64_t* pml4t = (uint64_t*)(eptp & ~0xFFFUL);
    bferror_subnhex(0, "pml4t", *pml4t);
    uint64_t* pdpt = (uint64_t*)(*pml4t & 0x0000FFFFFFFFF000);
    bferror_subnhex(0, "pdpt", *pdpt);
    auto ept_capabilities = ::intel_x64::msrs::get(0x48C);
    bferror_subnhex(0, "0x48C", ept_capabilities);
    return false;
}

static bool
handle_ept_violation(gsl::not_null<vmcs_t *> vmcs)
{
    //::intel_x64::vmcs::vm_entry_controls::ia_32e_mode_guest::disable();
    bfdebug_info(0, "ev");
    ::intel_x64::vmcs::secondary_processor_based_vm_execution_controls::enable_ept::disable();
    return true;
}

static bool
handle_monitor_trap(gsl::not_null<vmcs_t *> vmcs)
{
    // bferror_subnhex(0, "rip", ::intel_x64::vmcs::guest_rip::get());
    // bferror_subnhex(0, "activity state", ::intel_x64::vmcs::guest_activity_state::get());
    // ::intel_x64::vmcs::cr4_guest_host_mask::set(~0ULL);
    // ::intel_x64::vmcs::cr0_guest_host_mask::set(~0ULL);
    return true;
}

static bool
handle_wrcr0(gsl::not_null<vmcs_t *> vmcs, control_register::info_t &info)
{

    auto access_type = vmcs_n::exit_qualification::control_register_access::access_type::get();
    if (access_type == 2)
    {
        auto cur = vmcs_n::guest_cr0::get();
        info.shadow = info.shadow & ~vmcs_n::guest_cr0::task_switched::mask;
        info.val = cur & ~vmcs_n::guest_cr0::task_switched::mask;
    }
    else if (access_type == 3)
    {
        auto cur = vmcs_n::guest_cr0::get() & ~0xFFFFULL;
        info.val = cur | vmcs_n::exit_qualification::control_register_access::source_data::get();
        info.shadow &= ~0xFFFFULL;
        info.shadow |= info.shadow | vmcs_n::exit_qualification::control_register_access::source_data::get();
        info.val |= ::intel_x64::msrs::ia32_vmx_cr0_fixed0::get();
    }
    else if (access_type == 0)
    {
        info.shadow = info.val;
        info.val |= 0x30;
        //info.val |= ::intel_x64::msrs::ia32_vmx_cr0_fixed0::get();
        if (::intel_x64::vmcs::secondary_processor_based_vm_execution_controls::unrestricted_guest::is_enabled())
        {
            bfdebug_nhex(0, "mov to cr0", info.val);
            bfdebug_subnhex(0, "previously", vmcs_n::guest_cr0::get());
            info.val |= 0x60000030;
        }
    }
    else
    {
        throw std::runtime_error("handle_wrcr0 invalid access_type");
    }

    return true;
}

static bool
handle_wrcr4(gsl::not_null<vmcs_t *> vmcs, control_register::info_t &info)
{
    info.shadow = info.val;
    info.val = info.val | ::intel_x64::msrs::ia32_vmx_cr4_fixed0::get();
    // if (::intel_x64::vmcs::secondary_processor_based_vm_execution_controls::unrestricted_guest::is_enabled())
    //     bfdebug_nhex(0, "mov to cr4", info.val);

    return true;
}

static bool
handle_triple_fault(gsl::not_null<vmcs_t *> vmcs)
{
    ::intel_x64::vmcs::debug::dump();
    return false;
}

static bool
handle_hlt(gsl::not_null<vmcs_t *> vmcs)
{
    ::intel_x64::vmcs::debug::dump();
    // uint64_t cr3_p = ::intel_x64::cr3::get() & ~0xFFFULL;
    // bferror_subnhex(0, "cr3_p", cr3_p);
    // uint64_t cr3 = *(uint64_t*)cr3_p;
    // bferror_subnhex(0, "cr3", cr3);
    // cr3 = *(uint64_t*)(cr3_p+0x4);
    // bferror_subnhex(0, "cr3+4", cr3);
    // cr3 = *(uint64_t*)(cr3_p+0x8);
    // bferror_subnhex(0, "cr3+8", cr3);
    // cr3 = *(uint64_t*)(cr3_p+0xC);
    // bferror_subnhex(0, "cr3+C", cr3);
    return false;
}

static bool
handle_vmcall(gsl::not_null<vmcs_t *> vmcs)
{
    uint8_t core = thread_context_cpuid();
    uint16_t bf = 0xBF00;
    vmcs->save_state()->rax = (uint64_t)(bf|core);
    return advance(vmcs);
}

static bool
handle_init_signal(
    gsl::not_null<vmcs_t *> vmcs)
{
    //bfdebug_info(0, "init");
    ::intel_x64::vmcs::guest_activity_state::set(::intel_x64::vmcs::guest_activity_state::wait_for_sipi);
    return true;
}

static bool
handle_sipi(gsl::not_null<vmcs_t *> vmcs)
{
    //bfdebug_info(0, "sipi");
    // auto mmap = new eapis::intel_x64::ept::memory_map();

    // eapis::intel_x64::ept::identity_map_2m(*mmap, 0);
    // auto eptp = eapis::intel_x64::ept::eptp(*mmap);

    uint64_t* pml4t_p = (uint64_t*)bfvmm::memory_manager::instance()->alloc(0x1000); 
    uint64_t* pdpt_p = (uint64_t*)bfvmm::memory_manager::instance()->alloc(0x1000);
    uint64_t* pdt_p = (uint64_t*)bfvmm::memory_manager::instance()->alloc(0x1000);
    // auto pml4t_p = base1 & ~0xFFFULL; // supposed to come page aligned?
    // auto pdpt_p  = base2 & ~0xFFFULL;
    // auto eptp = pml4t_p; //>> 12;

    if (!pml4t_p || !pdpt_p || !pdt_p)
    {
        bferror_subnhex(0, "pml4t_p", pml4t_p);
        bferror_subnhex(0, "pdpt_p", pdpt_p);
        return false;
    }


    uint64_t pml4t = (uint64_t)pdpt_p | 0x7;
    *pml4t_p = pml4t;

    uint64_t pdpt = (uint64_t)pdt_p | 0x7;
    *pdpt_p = pdpt;

    uint64_t pdt = 0xC7ULL;
    *pdt_p = pdt;

    // for (int i = 0; i<512; i++)
    // {
    //     *pml4t_p = pml4t;
    //     pml4t_p++;
    // }

    // uint64_t pdpt = 0x487ULL | 1ULL<<63;
    // for (uint64_t i = 0; i<512; i++)
    // {
    //     *pdpt_p = pdpt | (i%64)<<30;
    //     pdpt_p++;
    // }

    uint64_t eptp = (uint64_t)pml4t_p | 0x18;
    ::intel_x64::vmcs::secondary_processor_based_vm_execution_controls::ept_mode_based_control::disable();
    ::intel_x64::vmcs::ept_pointer::set(eptp);
    ::intel_x64::vmcs::secondary_processor_based_vm_execution_controls::enable_ept::enable();
    ::intel_x64::vmcs::secondary_processor_based_vm_execution_controls::unrestricted_guest::enable();
    ::intel_x64::vmcs::vm_entry_controls::ia_32e_mode_guest::disable();

    ::intel_x64::vmcs::guest_cr0::set(0x60000030);
    //::intel_x64::vmcs::guest_cr0::set(::intel_x64::msrs::ia32_vmx_cr0_fixed0::get());
    ::intel_x64::vmcs::guest_cr3::set(0);
    ::intel_x64::vmcs::guest_cr4::set(0x00002000);
    //::intel_x64::vmcs::guest_cr4::set(::intel_x64::msrs::ia32_vmx_cr4_fixed0::get());

    ::intel_x64::cr2::set(0);
    ::intel_x64::cr8::set(0);

    auto vector_segment = ::intel_x64::vmcs::exit_qualification::sipi::vector::get() << 8;
    ::intel_x64::vmcs::guest_cs_selector::set(vector_segment);
    ::intel_x64::vmcs::guest_cs_base::set(vector_segment << 4);
    ::intel_x64::vmcs::guest_cs_limit::set(0xFFFF);
    ::intel_x64::vmcs::guest_cs_access_rights::set(0x9B);

    ::intel_x64::vmcs::guest_ds_selector::set(0);
    ::intel_x64::vmcs::guest_ds_base::set(0);
    ::intel_x64::vmcs::guest_ds_limit::set(0xFFFF);
    ::intel_x64::vmcs::guest_ds_access_rights::set(0x93);

    ::intel_x64::vmcs::guest_es_selector::set(0);
    ::intel_x64::vmcs::guest_es_base::set(0);
    ::intel_x64::vmcs::guest_es_limit::set(0xFFFF);
    ::intel_x64::vmcs::guest_es_access_rights::set(0x93);

    ::intel_x64::vmcs::guest_fs_selector::set(0);
    ::intel_x64::vmcs::guest_fs_base::set(0);
    ::intel_x64::vmcs::guest_fs_limit::set(0xFFFF);
    ::intel_x64::vmcs::guest_fs_access_rights::set(0x93);

    ::intel_x64::vmcs::guest_gs_selector::set(0);
    ::intel_x64::vmcs::guest_gs_base::set(0);
    ::intel_x64::vmcs::guest_gs_limit::set(0xFFFF);
    ::intel_x64::vmcs::guest_gs_access_rights::set(0x93);

    ::intel_x64::vmcs::guest_ss_selector::set(0);
    ::intel_x64::vmcs::guest_ss_base::set(0);
    ::intel_x64::vmcs::guest_ss_limit::set(0xFFFF);
    ::intel_x64::vmcs::guest_ss_access_rights::set(0x93);

    ::intel_x64::vmcs::guest_tr_selector::set(0);
    ::intel_x64::vmcs::guest_tr_base::set(0);
    ::intel_x64::vmcs::guest_tr_limit::set(0xFFFF);
    ::intel_x64::vmcs::guest_tr_access_rights::set(0x8B); //

    ::intel_x64::vmcs::guest_ldtr_selector::set(0);
    ::intel_x64::vmcs::guest_ldtr_base::set(0);
    ::intel_x64::vmcs::guest_ldtr_limit::set(0xFFFF);
    ::intel_x64::vmcs::guest_ldtr_access_rights::set(0x82); //

    ::intel_x64::vmcs::guest_gdtr_base::set(0);
    ::intel_x64::vmcs::guest_gdtr_limit::set(0xFFFF);

    ::intel_x64::vmcs::guest_idtr_base::set(0);
    ::intel_x64::vmcs::guest_idtr_limit::set(0xFFFF);

    vmcs->save_state()->rax = 0;
    vmcs->save_state()->rbx = 0;
    vmcs->save_state()->rcx = 0;
    vmcs->save_state()->rdx = 0xF00;
    vmcs->save_state()->rdi = 0;
    vmcs->save_state()->rsi = 0;
    vmcs->save_state()->rbp = 0;
    vmcs->save_state()->rsp = 0;
    vmcs->save_state()->rip = 0;
    
    ::intel_x64::vmcs::guest_rflags::set(0x2);
    ::intel_x64::vmcs::guest_ia32_efer::set(0);

    ::intel_x64::vmcs::guest_activity_state::set(::intel_x64::vmcs::guest_activity_state::active);

    //::intel_x64::vmcs::primary_processor_based_vm_execution_controls::monitor_trap_flag::enable();
    // ::intel_x64::vmcs::cr4_guest_host_mask::set(~0ULL);
    // ::intel_x64::vmcs::cr0_guest_host_mask::set(~0ULL);
    ::intel_x64::vmcs::primary_processor_based_vm_execution_controls::hlt_exiting::enable();

    //::intel_x64::vmcs::debug::dump();
    //bfvmm::intel_x64::check::all();

    return true;
}

// -----------------------------------------------------------------------------
// vCPU
// -----------------------------------------------------------------------------

using namespace ::intel_x64::vmcs;

class vcpu : public eapis::intel_x64::vcpu
{
public:

    vcpu(vcpuid::type id) :
        eapis::intel_x64::vcpu{id}
    {

        // ::intel_x64::vmcs::vmx_preemption_timer_value::set(5000000);
        // ::intel_x64::vmcs::pin_based_vm_execution_controls::activate_vmx_preemption_timer::enable();

        //::intel_x64::vmcs::cr4_guest_host_mask::set(::intel_x64::vmcs::host_cr4::vmx_enable_bit::mask);
        // ::intel_x64::vmcs::cr4_guest_host_mask::set(~0ULL);
        // ::intel_x64::vmcs::cr0_guest_host_mask::set(~0ULL);

        hve()->enable_wrcr0_exiting(
            0xFFFFFFFFFFFFFFFF, ::intel_x64::vmcs::guest_cr0::get()
        );

        hve()->add_wrcr0_handler(
            control_register::handler_delegate_t::create<handle_wrcr0>()
        );

        hve()->enable_wrcr4_exiting(
            0x2000, ::intel_x64::vmcs::guest_cr0::get()
        );

        hve()->add_wrcr4_handler(
            control_register::handler_delegate_t::create<handle_wrcr4>()
        );

        exit_handler()->add_handler(
            exit_reason::basic_exit_reason::cpuid,
            handler_delegate_t::create<handle_cpuid>());

        exit_handler()->add_handler(
            exit_reason::basic_exit_reason::rdmsr,
            handler_delegate_t::create<handle_rdmsr>());

        exit_handler()->add_handler(
            exit_reason::basic_exit_reason::init_signal,
            handler_delegate_t::create<handle_init_signal>());

        exit_handler()->add_handler(
            exit_reason::basic_exit_reason::sipi,
            handler_delegate_t::create<handle_sipi>());

        exit_handler()->add_handler(
            exit_reason::basic_exit_reason::vmx_preemption_timer_expired,
            handler_delegate_t::create<handle_vmx_preemption_timer_expired>());

        exit_handler()->add_handler(
            exit_reason::basic_exit_reason::ept_misconfiguration,
            handler_delegate_t::create<handle_ept_misconfiguration>());

        exit_handler()->add_handler(
            exit_reason::basic_exit_reason::ept_violation,
            handler_delegate_t::create<handle_ept_violation>());

        exit_handler()->add_handler(
            exit_reason::basic_exit_reason::monitor_trap_flag,
            handler_delegate_t::create<handle_monitor_trap>());

        // exit_handler()->add_handler(
        //     exit_reason::basic_exit_reason::hlt,
        //     handler_delegate_t::create<handle_hlt>());

        exit_handler()->add_handler(
            exit_reason::basic_exit_reason::triple_fault,
            handler_delegate_t::create<handle_triple_fault>());

        exit_handler()->add_handler(
            exit_reason::basic_exit_reason::wrmsr,
            handler_delegate_t::create<handle_wrmsr>());

        exit_handler()->add_handler(
            exit_reason::basic_exit_reason::vmcall,
            handler_delegate_t::create<handle_vmcall>());

        bfvmm::serial_ns16550a serial;
        serial.write('p');
        serial.write('p');
        serial.write('p');
        serial.write('p');
        serial.write('p');
        serial.write('p');
        serial.write('p');
        serial.write('p');
        serial.write('p');
        serial.write('\n');

    }

    ~vcpu()
    { }
};

}

// -----------------------------------------------------------------------------
// vCPU Factory
// -----------------------------------------------------------------------------

namespace bfvmm
{

std::unique_ptr<vcpu>
vcpu_factory::make_vcpu(vcpuid::type vcpuid, bfobject *obj)
{
    bfignored(obj);
    return std::make_unique<efi::vcpu>(vcpuid);
}

}



    // auto type = ::intel_x64::vmcs::exit_qualification::control_register_access::access_type::get();

    // if (type == 3)
    // {
    //     bferror_info(0, "cr access type 3");
    //     auto setter = (::intel_x64::vmcs::guest_cr0::get() & 0xFFFFFFFF00000000) | 
    //         ::intel_x64::vmcs::exit_qualification::control_register_access::source_data::get();
    //     ::intel_x64::vmcs::guest_cr0::set(setter);
    //     ::intel_x64::vmcs::cr0_read_shadow::set(setter);
    //     return advance(vmcs);
    // }
    // else if (type == 2)
    // {
    //     bferror_info(0, "cr access type 2");
    //     auto setter = intel_x64::vmcs::guest_cr0::get() & ~(1<<3ULL);
    //     ::intel_x64::vmcs::guest_cr0::set(setter);
    //     ::intel_x64::vmcs::cr0_read_shadow::set(setter);
    //     return advance(vmcs);
    // }

    // uint64_t* reg = (uint64_t*)vmcs->save_state();
    // reg += ::intel_x64::vmcs::exit_qualification::control_register_access::general_purpose_register::get();

    // if (type == 1)
    // {
    //     uint64_t getter = 0;
    //     if (::intel_x64::vmcs::exit_qualification::control_register_access::control_register_number::get() == 0)
    //     {
    //         *reg = ::intel_x64::vmcs::guest_cr0::get();
    //         return advance(vmcs);
    //     }
    //     else if (::intel_x64::vmcs::exit_qualification::control_register_access::control_register_number::get() == 0)
    //     {
    //         *reg = ::intel_x64::vmcs::guest_cr4::get();
    //         return advance(vmcs);
    //     }
    //     bferror_info(0, "cr access t1 false");
    //     return false;
    // }
    // else if (type == 0)
    // {
    //     auto setter = *reg;
    //     if (::intel_x64::vmcs::exit_qualification::control_register_access::control_register_number::get() == 0)
    //     {
    //         bferror_subnhex(0, "cr0 set", *reg);
    //         bferror_subnhex(0, "regn", ::intel_x64::vmcs::exit_qualification::control_register_access::general_purpose_register::get());
    //         if (setter == 0x60000000)
    //         {
    //             ::intel_x64::vmcs::guest_cr0::not_write_through::set(advance(vmcs));
    //             ::intel_x64::vmcs::guest_cr0::cache_disable::set(advance(vmcs));
    //             ::intel_x64::vmcs::cr0_read_shadow::set(::intel_x64::vmcs::cr0_read_shadow::get()|
    //                 ::intel_x64::vmcs::guest_cr0::not_write_through::mask|
    //                 ::intel_x64::vmcs::guest_cr0::cache_disable::mask);
    //             return advance(vmcs);
    //         }
    //         else if (setter == 0x40000000)
    //         {
    //             ::intel_x64::vmcs::guest_cr0::cache_disable::set(advance(vmcs));
    //             ::intel_x64::vmcs::cr0_read_shadow::set(::intel_x64::vmcs::cr0_read_shadow::get()|
    //                 ::intel_x64::vmcs::guest_cr0::cache_disable::mask);
    //             return advance(vmcs);
    //         }
    //         else if (setter == 0x20000000)
    //         {
    //             ::intel_x64::vmcs::guest_cr0::not_write_through::set(advance(vmcs));
    //             ::intel_x64::vmcs::cr0_read_shadow::set(::intel_x64::vmcs::cr0_read_shadow::get()|
    //                 ::intel_x64::vmcs::guest_cr0::not_write_through::mask);
    //             return advance(vmcs);
    //         }
    //         if (setter == 0)
    //         {
    //             ::intel_x64::vmcs::guest_cr0::not_write_through::set(false);
    //             ::intel_x64::vmcs::guest_cr0::cache_disable::set(false);
    //             ::intel_x64::vmcs::cr0_read_shadow::set(::intel_x64::vmcs::cr0_read_shadow::get()&
    //                 ~::intel_x64::vmcs::guest_cr0::not_write_through::mask&
    //                 ~::intel_x64::vmcs::guest_cr0::cache_disable::mask);
    //             return advance(vmcs);
    //         }
    //         ::intel_x64::vmcs::guest_cr0::set((*reg & ~::intel_x64::msrs::ia32_vmx_cr0_fixed0::get()) | 
    //             ::intel_x64::msrs::ia32_vmx_cr0_fixed1::get());
    //         ::intel_x64::vmcs::cr0_read_shadow::set(*reg);
    //         return advance(vmcs);
    //     }
    //     else if (::intel_x64::vmcs::exit_qualification::control_register_access::control_register_number::get() == 4)
    //     {
    //         bferror_subnhex(0, "cr4 set", *reg);
    //         ::intel_x64::vmcs::cr4_read_shadow::set(*reg);
    //         ::intel_x64::vmcs::guest_cr4::set(*reg);
    //         ::intel_x64::vmcs::guest_cr4::vmx_enable_bit::enable();
    //         ::intel_x64::vmcs::guest_cr4::physical_address_extensions::enable();
    //         return advance(vmcs);
    //     }
    //     bferror_info(0, "cr access t0 false");
    //     return false;
    // }

    // bferror_info(0, "cr access eof false");
    // return false;