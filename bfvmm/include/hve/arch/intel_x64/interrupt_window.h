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

#ifndef INTERRUPT_WINDOW_INTEL_X64_EAPIS_H
#define INTERRUPT_WINDOW_INTEL_X64_EAPIS_H

#include "base.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

class hve;

class EXPORT_EAPIS_HVE interrupt_window : public base
{
public:

    using handler_delegate_t = delegate<bool(gsl::not_null<vmcs_t *>)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    interrupt_window(gsl::not_null<eapis::intel_x64::hve *> hve);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~interrupt_window() = default;

public:

    /// Add Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the vector to listen to
    /// @param d the handler to call when an exit occurs
    ///
    void add_handler(handler_delegate_t &&d);

    /// Enable exiting
    ///
    /// @expects
    /// @ensures
    ///
    void enable_exiting();

    /// Disable exiting
    ///
    /// @expects
    /// @ensures
    ///
    void disable_exiting();

    /// Is open
    ///
    /// @expects
    /// @ensures
    ///
    ///
    bool is_open();

    /// Inject
    ///
    /// Inject an external interrupt at the given vector on the upcoming
    /// VM-entry
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the vector to inject into the VM
    ///
    void inject(uint64_t vector);

public:

    /// Dump Log
    ///
    /// Example:
    /// @code
    /// this->dump_log();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void dump_log() final;

    /// @cond

    bool handle(gsl::not_null<vmcs_t *> vmcs);

    /// @endcond

private:

    /// @cond

    std::list<handler_delegate_t> m_handlers{};

    /// @endcond

public:

    /// @cond

    interrupt_window(interrupt_window &&) = default;
    interrupt_window &operator=(interrupt_window &&) = default;

    interrupt_window(const interrupt_window &) = delete;
    interrupt_window &operator=(const interrupt_window &) = delete;

    /// @endcond
};

}
}

#endif
