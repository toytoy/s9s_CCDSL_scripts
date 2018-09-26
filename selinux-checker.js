#include "common/mysql_helper.js"

var DESCRIPTION="This advisor is to check if SELinux is set to Enforcing otherwise"
                " it's disabled or set as Permissive";
var TITLE="SELinux Check";
var ADVICE_WARNING="Warning!!! getenforce reveals it is set to Enforcing. Run &quot;setenforce permissive&quot; "
                   "or edit /etc/selinux/config and set SELINUX=disabled but this requires a host restart" ;
var ADVICE_OK="SELinux is Permissive or disabled" ;

function main()
{
    var hosts     = cluster::mySqlNodes();
    var advisorMap = {};

    var examinedHostnames = "";
    for (idx = 0; idx < hosts.size(); ++idx)
    {
        host        = hosts[idx];
        if (!host.connected())
            continue;

        if (examinedHostnames.contains(host.hostName()))
            continue;
        examinedHostnames += host.hostName();
        print("   ");
        print(host.hostName());
        print("==========================");
        map         = host.toMap();
        var advice = new CmonAdvice();



        retval = host.system("/sbin/getenforce |tr -d '\n'");
        reply = retval["result"].trim();
        if (!retval["success"])
        {
            var msg = "";
            if (reply.empty())
            {
                msg  = "Empty reply from the command. Assuming that "
                       "no SELinux found on this system";                      
                advice.setSeverity(Ok);
                advice.setJustification(msg);
                advice.setAdvice("Nothing to do.");
                
            }
            else
            {
                msg = "Check why the command failed: " + retval["errorMessage"];
                advice.setSeverity(Warning);
                advice.setJustification("Command failed.");
                advice.setAdvice("Check why the command failed: " +
                                  retval["errorMessage"]);
            }
            print(host.hostName() + ": " + msg);
        } else {
            var msg = "";
            
            if (reply.toLowerCase() == "enforcing")
            {
                msg  = "Set SELinux to Permissive or disable it";
                advice.setSeverity(Warning);
                advice.setJustification(msg);
                advice.setAdvice("Run &quot;setenforce permissive&quot; or set /etc/selinux/config. "
                 "Take note that disabling SELinux requires a server reboot");
            }
            else
            {
                advice.setSeverity(Ok);
                advice.setJustification("SELinux is set to permissive or disabled");
                advice.setAdvice(ADVICE_OK);
            }
            print(host.hostName() + ": " + msg);
        }
        advice.setHost(host);
        advice.setTitle(TITLE);
        advisorMap[idx]= advice;
        print(advice.toString("%E"));
    }
    return advisorMap;
}
