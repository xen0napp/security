#pragma once

#include <Windows.h>

#include <lazy_importer.hpp>
#include <xor_string.hpp>
#include <debugger.hpp>
#include <anti_dump.hpp>
#include <bad_process.hpp>
#include <anti_vm.hpp>
#include <ida.hpp>

namespace xen0n
{
	class security
	{
	private:
    /**
    * Crash OllyDbg 1.X
    * @return Returns an unsigned short with value 0
    */
		std::uint8_t kill_olly_dbg()
		{
			__try {
				(OutputDebugString)(TEXT("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s"));
			}
			__except (EXCEPTION_EXECUTE_HANDLER) { ; }

			return 0;
		}

		client::debugger* debugger;
		client::anti_dump* anti_dump;
		client::anti_vm* anti_vm;
		client::bad_processes* bad_processes;
		client::ida* ida;
	public:
    /**
    * Initialize the security modules and call anti_dump.
    * @return Returns an unsigned short with value 0
    */
		std::uint8_t init()
		{
			debugger = new client::debugger();
			anti_dump = new client::anti_dump();
			anti_vm = new client::anti_vm();
			bad_processes = new client::bad_processes();
			ida = new client::ida();

			anti_dump->null_size();

			return 0;
		}

    /**
    * Calls the security checks.
    * @return Returns an unsigned short with value 0
    */
		std::uint8_t call()
		{
			kill_olly_dbg();

			if (debugger->is_present() || debugger->remote_is_present() || debugger->thread_context() || debugger->hide_thread() || debugger->debug_string())
			{
				LI_FN(exit).safe()(0);
			}

			if (anti_vm->qemu() || anti_vm->vmware() || anti_vm->wine() || anti_vm->xen() || anti_vm->vbox() || anti_vm->vbox_registry())
			{
				LI_FN(exit).safe()(0);
			}

			if (bad_processes->check())
			{
				LI_FN(exit).safe()(0);
			}

			if (ida->check_history())
			{
				LI_FN(exit).safe()(0);
			}

			return 0;
		}
	};
}
