#pragma once

#include <Windows.h>
#include <lazy_importer.hpp>

namespace client
{
	class cpu
	{
	public:
		int debug_registers()
		{
			CONTEXT ctx = { 0 };
			const auto thread 
				= LI_FN(GetCurrentThread).safe()();

			ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
			if (LI_FN(GetThreadContext).safe()(thread, &ctx))
			{
				return ((ctx.Dr0 != 0x00) || (ctx.Dr1 != 0x00) || (ctx.Dr2 != 0x00) || (ctx.Dr3 != 0x00) || (ctx.Dr6 != 0x00) || (ctx.Dr7 != 0x00)) ? true : false;
			}

			return false;
		}
	};
}