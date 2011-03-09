{application, epcap,
 [
  {description, "libpcap port"},
  {vsn, "0.04"},
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
