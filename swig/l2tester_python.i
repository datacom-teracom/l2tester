
/* In Python, we need to typemap the exceptions. */
%typemap(throws) L2T::Exception
%{
    SWIG_Python_SetErrorMsg( PyExc_RuntimeError, $1.what() );
    SWIG_fail;
%}

%typemap(typecheck) (void* _packet, size_t _size)
%{
    $1 = PyString_Check( $input ) ? 1 : 0;
%}

%typemap(in) (void* _packet, size_t _size)
%{
    /* Check if is a string */
    if ( PyString_Check( $input ) ) {
        $1 = (void*) PyString_AsString( $input );
        $2 = (int) PyString_Size( $input );
    } else {
        PyErr_SetString( PyExc_TypeError, "Expected a string for packet." );
        return NULL;
    }
%}

%typemap(directorin) (void* _packet, size_t _size)
%{
    $input = PyBytes_FromStringAndSize( (char*) _packet, _size );
%}
