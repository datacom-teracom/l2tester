%module(directors="1") l2tester

%{
  #include "l2t_iterable.h"
  #include "l2t_exception.h"
  #include "l2t_logger.h"
  #include "l2t_interface.h"
  #include "l2t_sniffer.h"
  #include "l2t_sender.h"
  #include "l2t_bandwidth.h"
  #include "l2t_traffic_flow.h"
  #include "l2t_tunnel.h"
  #include "l2t_send_and_check.h"
%}

%include std_string.i
%include stl.i
%include stdint.i

namespace std {
	%template(VectorString) vector<string>;
	%template(MapStringToVectorString) map< string, vector<string> >;
}

#ifdef SWIGLUA
%include "l2tester_lua.i"
#endif

#ifdef SWIGPYTHON
%include "l2tester_python.i"
#endif

#ifdef SWIGRUBY
%include "l2tester_ruby.i"
#endif

%rename (TrafficFlow_Monitor) L2T::TrafficFlow::Monitor;
%rename (TrafficFlow_Event) L2T::TrafficFlow::Event;
%rename (TrafficFlow_Statistics) L2T::TrafficFlow::Statistics;

%rename (Bandwidth_Measure) L2T::Bandwidth::Measure;
%rename (Bandwidth_Stream) L2T::Bandwidth::Stream;
%rename (Bandwidth_Monitor) L2T::Bandwidth::Monitor;

/* Ingore helper classes from Logger module. */
%ingore L2T::Errno;
%ingore L2T::ByteArray;

%feature("director") L2T::Sniffer;

%include "../include/l2t_logger.h"
%include "../include/l2t_interface.h"
%include "../include/l2t_sniffer.h"
%include "../include/l2t_sender.h"
%include "../include/l2t_bandwidth.h"
%include "../include/l2t_traffic_flow.h"
%include "../include/l2t_tunnel.h"
%include "../include/l2t_send_and_check.h"
