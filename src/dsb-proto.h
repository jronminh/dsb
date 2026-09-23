// dsb wire protocol, shared by dsb.c (client) and dsbd.c (daemon).
//
// Transport: a unix stream socket, /run/dsb/IDENT.sock, one daemon instance
// per connection (systemd Accept=yes). No crypto: the kernel is the
// authority. The socket mode decides who can connect, and the daemon
// re-checks the caller's uid with SO_PEERCRED against dsb.conf before
// reading anything.
//
// 1. client -> daemon, one sendmsg:
//      SCM_RIGHTS: 3 fds, the command's stdin, stdout, stderr
//      data:       "DSBP" | u32 len | len bytes of NUL-terminated fields:
//                  version "2", mode, cwd, cwd_strict "0"|"1",
//                  argc, argv..., envc, env ("K=V")...
//    cwd "" means the identity's home. Integers are decimal strings.
//    Modes, all decided and carried out by the daemon:
//      cmd    argv is the command                           dsb CMD
//      shell  interactive shell, or argv through the shell  dsb, dsb -s
//      login  the same as a login shell                     dsb -i
//      line   argv[0] is a shell command line               dsb -c, -f
//      list   describe the identity (from dsb.conf)        dsb -l
//      which  where argv[0] resolves, and if it is allowed  dsb -l CMD
//      read   copy file argv[0] to stdout                   dsb -e
//      write  replace the contents of file argv[0] by stdin dsb -e
// 2. client -> daemon, any time after: 1 byte per signal to deliver to the
//    command's process group (SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGWINCH).
//    EOF (client gone) = SIGHUP, then the service's cgroup is torn down.
// 3. daemon -> client, once: "DSBP" | u8 status, then close. status is the
//    command's exit code, 128+N if it died of signal N, 124 if it ran past
//    the identity's timeout, 126 if it could not be executed, 127 if not
//    found, 1 if refused by policy; for read, 2 if the file does not exist.
//
// The command gets the caller's own fds, not a relay: no pty, no copying,
// pipes stay binary-clean, a terminal stays a terminal (window size, raw
// mode, all read straight from the device). Errors from the daemon itself
// are written to the passed stderr.
#ifndef DSB_PROTO_H
#define DSB_PROTO_H

#define DSB_MAGIC     "DSBP"
#define DSB_MAGIC_LEN 4
#define DSB_VERSION   "2"
#define DSB_REQ_MAX   (1024 * 1024)

#endif
