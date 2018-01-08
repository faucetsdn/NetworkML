The label_assignments.json file must be configured to include the proper prefixes for the packet captures (pcaps) that you would like to train from. The key is the filename prefix (which expects a dash afterwards), and the value is the label you would like to use. For example, if you have a directory full of pcaps such as:

Fileserver-Wed1220-0mins-n00.pcap, Iphone-Tues2320-0mins-n00.pcap

You might create an assignments.json file that looks like:
```
{
    "Iphone": "Smartphone",
    "Fileserver": "File server",
}
```
Also configure config.json file by adding "Smartphone" and "File server" labels to the label list, if they are not there.


### NOTE: 
The "-" i the filename is mandatory.
