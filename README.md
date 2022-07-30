# scper

This extremely overcomplicated and dense script was created to simplify the process of interacting with a remote server. It takes input parameters in a Metasploit-y way to define your list of servers, record access credentials, and define other system default parameters, such as default save location. 

```
usage: scper.py [-h] [-f] [-d [path]] [-u [path] [path]] [-e cmd [cmd ...]]
                [-v] [-r] [--PATH [path]] [--RHOST [ipv4:port]]
                [--USER [uname]] [--PASS [pwd]] [--TOKEN [path]]

uploads and downloads files via scp from remote host(s)

optional arguments:
  -h, --help           show this help message and exit
  -f                   force overwrite even if file already exists
  -d [path]            path to file or directory to download
  -u [path] [path]     path to file or directory to upload & upload location
  -e cmd [cmd ...]     execute command on remote host (enclose command in
                       "quotes")
  -v                   view or set the default server parameters
  -r                   remove one or more server parameters
  --PATH [path]        specify or change default save location
  --RHOST [ipv4:port]  add remote host (port is optional)
  --USER [uname]       add username for remote host
  --PASS [pwd]         add password for remote host (optional)
  --TOKEN [path]       add RSA token for remote host (optional)

v1.0.1b, created by toys0ldier (2022) https://github.com/toys0ldier
```

TODO: Lots of stuff... check back later.