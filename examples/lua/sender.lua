require 'l2tester'

num_args = table.getn( arg )

if num_args < 1 then
	print([[
  Usage: lua sender.lua <src>
  Arguments:
    src               : Source ethernet interface. Ex: eth0
]]);

else -- We have enough arguments

	local execute = function( src )
		-- TODO: Once we have proper typemaps for (void* _packet, size_t _size), create packet to be sent!
		local sender = l2tester.Sender( src, nil, 0 );
	end;

	status, err = pcall( execute, arg[1] );

	if not status then
		print( "ERROR: "..err );
	end;

end;

