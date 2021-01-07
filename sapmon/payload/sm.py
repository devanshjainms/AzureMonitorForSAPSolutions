import argparse
import daemon
import daemon.runner
import datetime
import lockfile
import os
import signal
import sys
import time

PIDFILE_NAME = "/tmp/sapmon.pid"

class sapmonDaemon:
   def run(args):
      while True:
         with open('/tmp/sapmon.txt', 'a') as fh:
            fh.write("{}\n".format(datetime.datetime.now()))
            time.sleep(10)

   # Start the daemon, if it's not already running
   def start(args):
      try:
         pidfile = daemon.runner.make_pidlockfile(PIDFILE_NAME,
                                                  acquire_timeout = 1)
      except lockfile.LockTimeout:
         print("sapmonDaemon is already running (timeout while acquiring lock)!")
         return
      if pidfile.is_locked():
         print("sapmonDaemon is already running (lockfile is locked)!")
         return
      if args.non_daemon:
         print("running in non-daemon")
         pass
      else:
         print("trying to start")
         with daemon.DaemonContext(pidfile = pidfile,
                                   signal_map = {
                                      signal.SIGTERM: sapmonDaemon.close,
                                      signal.SIGTSTP: sapmonDaemon.close,
                                   },
                                   stdout = sys.stdout
                                   ):
            sapmonDaemon.run(args)
      return

   def close(signum, frame):
      print("caught!")
      return

   def stop(args):
      try:
         with open(PIDFILE_NAME, "r") as pidfile:
            pid = int(pidfile.read().strip())
      except:
         print("sapmonDaemon is not running!")
         return

      try:
         os.kill(pid, signal.SIGKILL)
         os.remove(PIDFILE_NAME)
      except ProcessLookupError:
         print("sapmonDaemon is not running!")
         return


class sapmon:
   def __init__(self):
      parser = argparse.ArgumentParser(prog = "sapmon",
                                       usage = """sapmon [<command>] [<options]

Available commands:
  start       Start sapmon daemon :)
  stop        Stop  sapmon daemon :(
  reconfig    Fetch config without restarting
""")
      if len(sys.argv) == 1:
         parser.print_help()
         return
      parser.add_argument("command", help="Command to run")
      args = parser.parse_args(sys.argv[1:2])
      if not hasattr(self, args.command) or args.command.startswith("__"):
         print("Unknown command: %s" % args.command)
         parser.print_help()
         return
      getattr(self, args.command)()

   def start(self):
      args = argparse.ArgumentParser(prog = "sapmon start")
      args.add_argument("-n",
                        "--non-daemon",
                        help = "run sapmon once in non-daemon mode",
                        action = "store_true")
      args = args.parse_args(sys.argv[2:])
      sapmonDaemon.start(args)

   def stop(self):
      args = argparse.ArgumentParser(prog = "sapmon stop")
      sapmonDaemon.stop()

   def reconfig(self):
      print("reconfig")

if __name__ == "__main__":
   sapmon()