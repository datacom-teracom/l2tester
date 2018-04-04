
/* Even if in Ruby exceptions are natively supported, the message associated was not displayed. */
%typemap(throws) L2T::Exception
%{
	static VALUE l2t_error = rb_define_class("L2T::Exception", rb_eStandardError);
    rb_raise( l2t_error, $1.what() );
    SWIG_fail;
%}

%typemap(typecheck) (void* _packet, size_t _size)
%{
    $1 = TYPE( $input ) == T_STRING ? 1 : 0;
%};

%typemap(in) (void* _packet, size_t _size)
%{
    /* Check if is a string */
    if ( TYPE($input) == T_STRING ) {
        $1 = (void*) StringValuePtr( $input );
        $2 = (int) RSTRING_LEN( $input );
    } else {
         rb_raise( rb_eTypeError, "Expected a string for packet." );
        return NULL;
    }
%}

%typemap(directorin) (void* _packet, size_t _size)
%{
    $input = rb_str_new( (char*) _packet, _size );
%}
