
/* In Lua, we must typemap user defined exceptions. */
%typemap(throws) L2T::Exception
%{
    lua_pushstring( L, $1.what() ); // Push the error message
    SWIG_fail;                      // trigger the error handler
%}

%typemap(typecheck) (void* _packet, size_t _size)
%{
    $1 = lua_isstring(L, $input);
%}

%typemap(in) (void* _packet, size_t _size)
%{
    /* Check if is a string */
    $1 = (void*) luaL_checklstring(L, $input, &$2);
%}
