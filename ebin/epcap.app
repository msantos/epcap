{application, epcap,
 [
  {description, "libpcap port"},
  {vsn, "0.05"},
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
  {env, []}
 ]}.
