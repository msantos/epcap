{application, epcap,
 [
  {description, "libpcap port"},
  {vsn, "0.03"},
  {modules, [
      epcap,
      epcap_net,
      sniff
          ]},
  {registered, [epcap]},
  {applications, [
                  kernel,
                  stdlib
                 ]},
  {mod, {epcap_app, []}},
  {env, []}
 ]}.
