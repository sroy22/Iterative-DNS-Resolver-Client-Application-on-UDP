package ca.ubc.cs.cs317.dnslookup;

import java.io.*;
import java.net.*;
import java.util.*;

public class DNSLookupService {

    private static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL = 10;

    private static InetAddress rootServer;
    private static boolean verboseTracing = false;
    private static DatagramSocket socket;

    private static DNSCache cache = DNSCache.getInstance();

    private static Random random = new Random();
    private static int cur=0;

    /**
     * Main function, called when program is first invoked.
     *
     * @param args list of arguments specified in the command line.
     */
    public static void main(String[] args) {

        if (args.length != 1) {
            System.err.println("Invalid call. Usage:");
            System.err.println("\tjava -jar DNSLookupService.jar rootServer");
            System.err.println("where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
            System.exit(1);
        }

        try {
            rootServer = InetAddress.getByName(args[0]);
            System.out.println("Root DNS server is: " + rootServer.getHostAddress());
        } catch (UnknownHostException e) {
            System.err.println("Invalid root server (" + e.getMessage() + ").");
            System.exit(1);
        }

        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(5000);
        } catch (SocketException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

        Scanner in = new Scanner(System.in);
        Console console = System.console();
        do {
            // Use console if one is available, or standard input if not.
            String commandLine;
            if (console != null) {
                System.out.print("DNSLOOKUP> ");
                commandLine = console.readLine();
            } else
                try {
                    System.out.print("DNSLOOKUP> "); // ADD THIS
                    commandLine = in.nextLine();
                } catch (NoSuchElementException ex) {
                    break;
                }
            // If reached end-of-file, leave
            if (commandLine == null) break;

            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];

            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty()) continue;

            String[] commandArgs = commandLine.split(" ");

            if (commandArgs[0].equalsIgnoreCase("quit") ||
                    commandArgs[0].equalsIgnoreCase("exit"))
                break;
            else if (commandArgs[0].equalsIgnoreCase("server")) {
                // SERVER: Change root nameserver
                if (commandArgs.length == 2) {
                    try {
                        rootServer = InetAddress.getByName(commandArgs[1]);
                        System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
                    } catch (UnknownHostException e) {
                        System.out.println("Invalid root server (" + e.getMessage() + ").");
                        continue;
                    }
                } else {
                    System.out.println("Invalid call. Format:\n\tserver IP");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("trace")) {
                // TRACE: Turn trace setting on or off
                if (commandArgs.length == 2) {
                    if (commandArgs[1].equalsIgnoreCase("on"))
                        verboseTracing = true;
                    else if (commandArgs[1].equalsIgnoreCase("off"))
                        verboseTracing = false;
                    else {
                        System.err.println("Invalid call. Format:\n\ttrace on|off");
                        continue;
                    }
                    System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
                } else {
                    System.err.println("Invalid call. Format:\n\ttrace on|off");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("lookup") ||
                    commandArgs[0].equalsIgnoreCase("l")) {
                // LOOKUP: Find and print all results associated to a name.
                RecordType type;
                if (commandArgs.length == 2)
                    type = RecordType.A;
                else if (commandArgs.length == 3)
                    try {
                        type = RecordType.valueOf(commandArgs[2].toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
                        continue;
                    }
                else {
                    System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
                    continue;
                }
                findAndPrintResults(commandArgs[1], type);
            } else if (commandArgs[0].equalsIgnoreCase("dump")) {
                // DUMP: Print all results still cached
                cache.forEachNode(DNSLookupService::printResults);
            } else {
                System.err.println("Invalid command. Valid commands are:");
                System.err.println("\tlookup fqdn [type]");
                System.err.println("\ttrace on|off");
                System.err.println("\tserver IP");
                System.err.println("\tdump");
                System.err.println("\tquit");
                continue;
            }

        } while (true);

        socket.close();
        System.out.println("Goodbye!");
    }

    /**
     * Finds all results for a host name and type and prints them on the standard output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {

        DNSNode node = new DNSNode(hostName, type);
        printResults(node, getResults(node, 0));
    }

    /**
     * Finds all the result for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
     *                         The initial call should be made with 0 (zero), while recursive calls for
     *                         regarding CNAME results should increment this value by 1. Once this value
     *                         reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
     *                         returns an empty set.
     * @return A set of resource records corresponding to the specific query requested.
     */
    private static void receiveDecode(byte[] receiveBuffer) {
        int receiveID = ((receiveBuffer[0] & 0xFF) << 8) + (receiveBuffer[1] & 0xFF);
        System.out.println("ReceiveID"+ receiveID);

        int QCOUNT = ((receiveBuffer[4] & 0xFF) << 8) + (receiveBuffer[5] & 0xFF);
        System.out.println("QCOUNT"+ QCOUNT);
        int ANSCOUNT = ((receiveBuffer[6] & 0xFF) << 8) + (receiveBuffer[7] & 0xFF);
        System.out.println("ANSCOUNT"+ ANSCOUNT);
        int AUTHORITYCOUNT = ((receiveBuffer[8] & 0xFF) << 8) + (receiveBuffer[9] & 0xFF);
        System.out.println("AUTHORITYCOUNT"+ AUTHORITYCOUNT);
        int ADDCOUNT = ((receiveBuffer[10] & 0xFF) << 8) + (receiveBuffer[11] & 0xFF);
        System.out.println("ADDCOUNT"+ ADDCOUNT);
         cur = 12; // starting from Question section
        int len = 1;
        String qName = "";
        while (len > 0) {
            len = (receiveBuffer[cur] & 0xFF);
            cur++; // go to next byte
            if (len == 0)
                break; // when 00
            for (int i = 0; i < len; i++) {
                qName = qName + (char) (receiveBuffer[cur] & 0xff);
                cur++;
            }
            qName = qName + ".";
        }

        System.out.println("QNAME"+ qName);
        int qTYPE = ((receiveBuffer[cur++] & 0xFF) << 8) + (receiveBuffer[cur++] & 0xFF);
        System.out.println("QTYPE"+ qTYPE);
        int QCLASS = ((receiveBuffer[cur++] & 0xFF) << 8) + (receiveBuffer[cur++] & 0xFF);
        System.out.println("QCLASS"+ QCLASS);

        String recordName=getNameFromRecord(cur,receiveBuffer);
        int typeVal=((receiveBuffer[cur++] & 0xFF) << 8) + (receiveBuffer[cur++] & 0xFF);
        System.out.println("TYPECODE"+typeVal);
        int classVal=((receiveBuffer[cur++] & 0xFF) << 8) + (receiveBuffer[cur++] & 0xFF);
        System.out.println("CLASSCODE"+ classVal);
        long TTL= ((receiveBuffer[cur++] & 0xFF) << 24) + ((receiveBuffer[cur++] & 0xFF) << 16) + ((receiveBuffer[cur++] & 0xFF) << 8) + (receiveBuffer[cur++] & 0xFF);
        System.out.println("TTL"+TTL);
        int RDATALen=((receiveBuffer[cur++] & 0xFF) << 8) + (receiveBuffer[cur++] & 0xFF);
        System.out.println("RDATALENGTH"+ RDATALen);
        if(typeVal==2)
            System.out.println(getNameFromRecord(cur,receiveBuffer));
        if(typeVal==1)
        {
            String ipAdress="";
            for(int i=0;i<RDATALen;i++)
                ipAdress=ipAdress+(receiveBuffer[cur++] & 0xff)+".";
            ipAdress.substring(0,ipAdress.length()-1);
            System.out.println("IPADRESS"+ipAdress);
        }
    }
    private static String getNameFromRecord(int num, byte[] receiveBuffer) {

        int len = 1;
        String rName = "";
        while (len > 0) {
            len = (receiveBuffer[num] & 0xFF);
            num++; // go to next byte
            if (len == 0)
                break; // when 00
            else if (len == 192) {
                int newNum = (receiveBuffer[num] & 0xFF);
                num++;
                rName = rName + getNameFromRecord(newNum, receiveBuffer);
                break;
            } else {
                for (int i = 0; i < len; i++) {
                    rName = rName + (char) (receiveBuffer[num] & 0xff);
                    num++;
                }
                rName = rName + ".";
            }

        }
        cur=num;
        return rName;
    }
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {

        if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }

        // TODO To be completed by the student
        System.out.println(node.getHostName());
        ByteArrayOutputStream bOutput = new ByteArrayOutputStream();
        DataOutputStream dOutput = new DataOutputStream(bOutput);
        try
        {
        	dOutput.writeShort(0x0001); // random query id
        	dOutput.writeShort(0x0100); // query flags
        	dOutput.writeShort(0x0001);
        	dOutput.writeShort(0x0000);
        	dOutput.writeShort(0x0000);
        	dOutput.writeShort(0x0000);
        	
        	String[] parts= node.getHostName().split("\\.");
        	for(int i=0;i<parts.length;i++)
        		{
        		byte[] partBytes=parts[i].getBytes("UTF-8");
        		dOutput.writeByte(parts[i].length());
        		dOutput.write(partBytes);
        		System.out.println(parts[i]);
        		}
        	dOutput.writeByte(0x00);
        	dOutput.writeShort(0x0001);
        	dOutput.writeShort(0x0001);

        	byte[] byteArray=bOutput.toByteArray();
        	DatagramPacket requestPacket= new DatagramPacket(byteArray,byteArray.length,rootServer,DEFAULT_DNS_PORT);
        	socket=new DatagramSocket();
        	socket.send(requestPacket);
            byte[] bufferReceive = new byte[1024];
            DatagramPacket receivePacket = new DatagramPacket(bufferReceive, bufferReceive.length);
            socket.receive(receivePacket);
            receiveDecode(bufferReceive);
            /*
            //for(int i=0;i<bufferReceive.length;i++)
             //   System.out.println(bufferReceive[i]);
            System.out.println("\n\nReceived: " + receivePacket.getLength() + " bytes");
            DataInputStream readByte = new DataInputStream(new ByteArrayInputStream(bufferReceive));
            /*StringBuffer sb = new StringBuffer();
            /*for (byte b : bufferReceive) {
                sb.append(Integer.toHexString((int) (b & 0xff)));
            }
            */
            /*
            StringBuilder sb = new StringBuilder();

            for (byte b : bufferReceive) {
                sb.append(String.format("%02X ", b));
            }

            String finalResponse=sb.toString();
            String[] response=finalResponse.split("\\s+");
            for(int i=0;i<response.length;i++)
                System.out.println(response[i]);
            System.out.println("Query ID" +response[0]+response[1]);
            System.out.println("Flags"+ response[2]+response[3]);
            System.out.println("Question"+response[4]+response[5]);
            System.out.println("Answer"+response[6]+response[7]);
            System.out.println("Authority"+response[8]+response[9]);
            System.out.println("Additional"+response[10]+response[11]);

            int num=12;
            while(!response[num].equals("00"))
            {
                int len=Integer.parseInt(response[num],16);
                int i;
                for( i=num+1;i<=(num+len);i++)
                    System.out.println((char)In

                            teger.parseInt(response[i],16));
                num=i;


            }


            System.out.println("THIS");
            */
        }
        catch(IOException e)
        {
        	
        }
        finally
        {
        	
        }
        return cache.getCachedResults(node);
    }

    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
     * and the query is repeated with a new server if the provided one is non-authoritative.
     * Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static void retrieveResultsFromServer(DNSNode node, InetAddress server) {

        // TODO To be completed by the student
    }

    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }

    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results) {
        if (results.isEmpty())
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results) {
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), record.getTTL(), record.getTextResult());
        }
    }
}
