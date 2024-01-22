#!/usr/bin/python

import sys
import os
import datetime
import signal
import argparse
import logging
from threading import Timer
from concurrent import futures

import grpc

import ui_pb2
from  ui_pb2_grpc import add_UIServicer_to_server


def on_exit():
    """
    TODO explain
    """
    server.stop(0)

    # try to exit gracefully.
    Timer(5, __force_exit__).start()
    sys.exit(0)


def __force_exit__():
    """
    TODO explain
    """
    os._exit(1)


class Servicer():
    def Ping(self, request, context):
        """
        Example: 
        request:
        events {
            unixnano: 12i3612387123.
            time: "2022",
            connection {
                protocol: "udp"
                src_ip: "192.168.188.21"
                src_port: 58819
                dst_ip: "192.168.188.1"
                dst_host: "ping.archlinux.org"
                dst_port: 53
                process_id: 23334
                process_path: "/usr/bin/NetworkManager"
                process_cwd: "/"
                process_args: "/usr/bin/NetworkManager"
                process_args: "--no-daemon"
                process_env {
                  key: "INVOCATION_ID"
                  value: "7ca46c19664b4377b846b362e08ac731"
                }
            }
            rule {
              name: "allow-simple-usrbinnetworkmanager"
              enabled: true
              action: "allow"
              duration: "always"
              operator {
                type: "simple"
                operand: "process.path"
                data: "/usr/bin/NetworkManager"
              }
            }
        }

          by_executable {
    key: "/usr/lib/thunderbird/thunderbird"
    value: 1221
  }

  stats {
        daemon_version: "1.5.0rc2"
        rules: 42
        uptime: 101324
        dns_responses: 51030
        connections: 78799
        accepted: 128532
        dropped: 1297
        rule_hits: 78174
        rule_misses: 625
        by_port {
          key: "993"
          value: 108
        }
        by_uid {
          key: "0"
          value: 5750
        }
        by_host {
          key: "thume.ca"
          value: 84
        }
        by_address {
          key: "2a05:3e00:9:1001::222:4"
          value: 44
        }
        by_proto {
          key: "tcp"
          value: 16645
        }
    }
        """
        print("Ping", request)
        sys.exit(1)

        try:
            self._last_ping = datetime.now()
            if Utils.check_versions(request.stats.daemon_version):
                self._version_warning_trigger.emit(request.stats.daemon_version, version)

            proto, addr = self._get_peer(context.peer())
            # do not update db here, do it on the main thread
            self._update_stats_trigger.emit(proto, addr, request)

        except Exception as e:
            print("Ping exception: ", e)

        return ui_pb2.PingReply(id=request.id)

    def AskRule(self, request, context):
        print("AskRule")  # , request)
        exit(1)
        #def callback(ntf, action, connection):
        # TODO

        #if self._desktop_notifications.support_actions():
        #    self._desktop_notifications.ask(request, callback)

        # TODO: allow connections originated from ourselves: os.getpid() == request.pid)
        self._asking = True
        proto, addr = self._get_peer(context.peer())
        rule, timeout_triggered = self._prompt_dialog.promptUser(request, self._is_local_request(proto, addr), context.peer())
        self._last_ping = datetime.now()
        self._asking = False
        if rule == None:
            return None

        if timeout_triggered:
            _title = request.process_path
            if _title == "":
                _title = "%s:%d (%s)" % (request.dst_host if request.dst_host != "" else request.dst_ip, request.dst_port, request.protocol)


            node_text = "" if self._is_local_request(proto, addr) else "on node {0}:{1}".format(proto, addr)
            self._show_message_trigger.emit(_title,
                                            "{0} action applied {1}\nCommand line: {2}"
                                            .format(rule.action, node_text, " ".join(request.process_args)),
                                            QtWidgets.QSystemTrayIcon.NoIcon)

        if rule.duration in Config.RULES_DURATION_FILTER:
            self._node_actions_trigger.emit(
                {
                    'action': self.DELETE_RULE,
                    'name': rule.name,
                    'addr': context.peer()
                }
            )
        else:
            self._node_actions_trigger.emit(
                {
                    'action': self.ADD_RULE,
                    'peer': context.peer(),
                    'rule': rule
                }
            )

        return rule

    def Subscribe(self, node_config, context):
        """
        Accept and collect nodes. It keeps a connection open with each
        client, in order to send them notifications.

        @doc: https://grpc.github.io/grpc/python/grpc.html#service-side-context
        """
        print("subscribe")#, node_config, context)
        exit(1)

        # if the exit mark is set, don't accept new connections.
        # db vacuum operation may take a lot of time to complete.
        if self._exit:
            return
        try:
            self._node_actions_trigger.emit({
                    'action': self.NODE_ADD,
                    'peer': context.peer(),
                    'node_config': node_config
                 })
            # force events processing, to add the node ^ before the
            # Notifications() call arrives.
            self._app.processEvents()

            proto, addr = self._get_peer(context.peer())
            if self._is_local_request(proto, addr) == False:
                self._show_message_trigger.emit(
                    QtCore.QCoreApplication.translate("stats", "New node connected"),
                    "({0})".format(context.peer()),
                    QtWidgets.QSystemTrayIcon.Information)
        except Exception as e:
            print("[Notifications] exception adding new node:", e)
            context.cancel()

        node_config.config = self._overwrite_nodes_config(node_config.config)

        return node_config

    def Notifications(self, node_config, context):
        """
        Accept and collect nodes. It keeps a connection open with each
        client, in order to send them notifications.

        @doc: https://grpc.github.io/grpc/python/grpc.html#service-side-context
        @doc: https://grpc.io/docs/what-is-grpc/core-concepts/
        """
        print("notifi")#, node_config, context)
        exit(1)

        proto, addr = self._get_peer(context.peer())
        _node = self._nodes.get_node("%s:%s" % (proto, addr))
        if _node == None:
            return

        stop_event = Event()
        def _on_client_closed():
            stop_event.set()
            self._node_actions_trigger.emit(
                {'action': self.NODE_DELETE,
                 'peer': context.peer(),
                 })

            self._status_change_trigger.emit(False)
            # TODO: handle the situation when a node disconnects, and the
            # remaining node has the fw disabled.
            #if self._nodes.count() == 1:
            #    nd = self._nodes.get_nodes()
            #    if nd[0].get_config().isFirewallRunning:

            if self._is_local_request(proto, addr) == False:
                self._show_message_trigger.emit("node exited",
                                    "({0})".format(context.peer()),
                                    QtWidgets.QSystemTrayIcon.Information)

        context.add_callback(_on_client_closed)

        # TODO: move to notifications.py
        def new_node_message():
            print("new node connected, listening for client responses...", addr)

            while self._exit == False:
                try:
                    if stop_event.is_set():
                        break
                    in_message = next(node_iter)
                    if in_message == None:
                        continue

                    self._nodes.reply_notification(addr, in_message)
                except StopIteration:
                    print("[Notifications] Node {0} exited".format(addr))
                    break
                except grpc.RpcError as e:
                    print("[Notifications] grpc exception new_node_message(): ", addr, in_message)
                except Exception as e:
                    print("[Notifications] unexpected exception new_node_message(): ", addr, e, in_message)

        read_thread = Thread(target=new_node_message)
        read_thread.daemon = True
        read_thread.start()

        while self._exit == False:
            if stop_event.is_set():
                break

            try:
                noti = _node['notifications'].get()
                if noti != None:
                    _node['notifications'].task_done()
                    yield noti
            except Exception as e:
                print("[Notifications] exception getting notification from queue:", addr, e)
                context.cancel()

        return node_iter


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='OpenSnitch cli interface.')
    parser.add_argument("--socket", dest="socket", 
                        default="unix:///tmp/osui.sock", 
                        help="Path of the unix socket for the gRPC service"
                        "(https://github.com/grpc/grpc/blob/master/doc/naming.md).",
                        metavar="FILE")
    parser.add_argument("--text")
    args = parser.parse_args()
    servicer = Servicer()

    # @doc: https://grpc.github.io/grpc/python/grpc.html#server-object
    server = grpc.server(futures.ThreadPoolExecutor(),
                         options=(
                             # https://github.com/grpc/grpc/blob/master/doc/keepalive.md
                             # https://grpc.github.io/grpc/core/group__grpc__arg__keys.html
                             # send keepalive ping every 5 second, default is 2 hours)
                             ('grpc.keepalive_time_ms', 5000),
                             # after 5s of inactivity, wait 20s and close the connection if
                             # there's no response.
                             ('grpc.keepalive_timeout_ms', 20000),
                             ('grpc.keepalive_permit_without_calls', True),
                         ))

    if args.socket.startswith("unix://"):
        socket = args.socket[7:]
        socket = os.path.abspath(socket)
        server.add_insecure_port("unix:%s" % socket)
    else:
        server.add_insecure_port(args.socket)

    add_UIServicer_to_server(servicer, server)

    # https://stackoverflow.com/questions/5160577/ctrl-c-doesnt-work-with-pyqt
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    try:
        print("service running on %s ..." % socket)
        server.start()
        server.wait_for_termination()
    except KeyboardInterrupt:
        on_exit()
