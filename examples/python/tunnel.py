
import l2tester
import sys, time

#l2tester.Logger.config_log_level( l2tester.Logger.L2T_LOG_DEBUG ) 

if len(sys.argv) < 3 :

	print """
  Usage: python tunnel.py <src> <dst>
  Arguments
    src               : Source ethernet interface. Ex: eth0
    dst               : Destination ethernet interface. Ex: eth1
  """

else:

	try:
		tunnel = l2tester.Tunnel( sys.argv[1], sys.argv[2] )
		while True:
			time.sleep(1)

	except Exception as e:
		print e
