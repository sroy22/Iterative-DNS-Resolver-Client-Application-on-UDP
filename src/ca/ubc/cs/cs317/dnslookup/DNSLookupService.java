package ca.ubc.cs.cs317.dnslookup;

import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.DataOutputStream;
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
    private static int cur = 0;
    private static Set<Integer> queryIDs = new HashSet<>();
    private static int queryID;

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

    private static ResourceRecord decodeRecord(byte[] receiveBuffer) {
        String recordName = getNameFromRecord(cur, receiveBuffer);
        int typeVal = ((receiveBuffer[cur++] & 0xFF) << 8) + (receiveBuffer[cur++] & 0xFF);
//        System.out.println("TYPECODE " + typeVal);
        int classVal = ((receiveBuffer[cur++] & 0xFF) << 8) + (receiveBuffer[cur++] & 0xFF);
//        System.out.println("CLASSCODE " + classVal);
        long TTL = ((receiveBuffer[cur++] & 0xFF) << 24) + ((receiveBuffer[cur++] & 0xFF) << 16) + ((receiveBuffer[cur++] & 0xFF) << 8) + (receiveBuffer[cur++] & 0xFF);
//        System.out.println("TTL " + TTL);
        int RDATALen = ((receiveBuffer[cur++] & 0xFF) << 8) + (receiveBuffer[cur++] & 0xFF);
//        System.out.println("RDATALENGTH " + RDATALen);
        ResourceRecord record = null;
        switch (typeVal) {
            case 1: // Type A
                String ipAddress = "";
                for (int i = 0; i < RDATALen; i++) {
                    ipAddress = ipAddress + (receiveBuffer[cur++] & 0xff) + ".";
                }
                ipAddress = ipAddress.substring(0, ipAddress.length() - 1);
//                System.out.println("IPADDRESS " + ipAddress);
                try {
                    record = new ResourceRecord(recordName, RecordType.getByCode(typeVal), TTL, InetAddress.getByName(ipAddress));
                } catch (Exception e) {

                }
                break;
            case 2: // Type NS
            case 5: // Type CNAME
                String name = getNameFromRecord(cur, receiveBuffer);
                System.out.println(name);
                try {
                    record = new ResourceRecord(recordName, RecordType.getByCode(typeVal), TTL, name);
                } catch (Exception e) {

                }
                break;
            case 28: // Type AAAA IPv6
                String ipv6Address = "";
                for (int i = 0; i < RDATALen / 2; i++) { // 8 octets, length 16
                    ipv6Address = ipv6Address +
                            Integer.toHexString(((receiveBuffer[cur++] & 0xFF) << 8) + (receiveBuffer[cur++] & 0xFF))
                            + ":";
                }
                ipv6Address = ipv6Address.substring(0, ipv6Address.length() - 1);
//                System.out.println("IPADDRESS " + ipv6Address);
                try {
                    record = new ResourceRecord(recordName, RecordType.getByCode(typeVal), TTL, InetAddress.getByName(ipv6Address));
                    verbosePrintResourceRecord(record, 28); // other has rtype 0
                } catch (Exception e) {

                }
                break;
            default:
                record = null;
                break;
        }

        if (record != null) {
            cache.addResult(record);
        }

        return record;
    }

    private static ArrayList<ResourceRecord> receiveDecode(byte[] receiveBuffer) {
        int receiveID = ((receiveBuffer[0] & 0xFF) << 8) + (receiveBuffer[1] & 0xFF);
        System.out.println("ReceiveID " + receiveID);
        if (queryID != receiveID) {
            return null;
        }

        int AA = (receiveBuffer[2] & 0x04) >>> 2;

        int QCOUNT = ((receiveBuffer[4] & 0xFF) << 8) + (receiveBuffer[5] & 0xFF);
        System.out.println("QCOUNT " + QCOUNT);
        int ANSCOUNT = ((receiveBuffer[6] & 0xFF) << 8) + (receiveBuffer[7] & 0xFF);
        System.out.println("ANSCOUNT " + ANSCOUNT);
        int AUTHORITYCOUNT = ((receiveBuffer[8] & 0xFF) << 8) + (receiveBuffer[9] & 0xFF);
        System.out.println("AUTHORITYCOUNT " + AUTHORITYCOUNT);
        int ADDCOUNT = ((receiveBuffer[10] & 0xFF) << 8) + (receiveBuffer[11] & 0xFF);
        System.out.println("ADDCOUNT " + ADDCOUNT);

        cur = 12; // starting from Question section 12 byte
        String qName = "";
        while (true) {
            int length = (receiveBuffer[cur] & 0xFF);
            cur++; // go to next byte
            if (length == 0)
                break; // when 00
            for (int i = 0; i < length; i++) {
                qName = qName + (char) (receiveBuffer[cur] & 0xff);
                cur++;
            }
            qName = qName + ".";
        }

//        System.out.println("QNAME " + qName);
        int qTYPE = ((receiveBuffer[cur++] & 0xFF) << 8) + (receiveBuffer[cur++] & 0xFF);
//        System.out.println("QTYPE " + qTYPE);
        int QCLASS = ((receiveBuffer[cur++] & 0xFF) << 8) + (receiveBuffer[cur++] & 0xFF);
//        System.out.println("QCLASS " + QCLASS);

        ArrayList<ResourceRecord> answers = new ArrayList<>();
        ArrayList<ResourceRecord> nameServers = new ArrayList<>();
        ArrayList<ResourceRecord> additionalServers = new ArrayList<>();
        ResourceRecord r;

        for (int i = 0; i < ANSCOUNT; i++) {
            r = decodeRecord(receiveBuffer);
            if (r != null) {
                answers.add(r);
            }
        }

        for (int i = 0; i < AUTHORITYCOUNT; i++) {
            r = decodeRecord(receiveBuffer);
            if (r != null) {
                nameServers.add(r);
            }
        }

        for (int i = 0; i < ADDCOUNT; i++) {
            r = decodeRecord(receiveBuffer);
            if (r != null) {
                additionalServers.add(r);
            }
        }

        if (AA == 0) {
            ArrayList<ResourceRecord> AANameServers = new ArrayList<>();
            for (ResourceRecord nameServer : nameServers) {
                for (ResourceRecord additionalServer : additionalServers) {
                    if (additionalServer.getTextResult().equals(nameServer.getTextResult()) &&
                            additionalServer.getType().getCode() == 1) {
                        AANameServers.add(additionalServer);
                    }
                }
            }

            if (!AANameServers.isEmpty()) {
                return AANameServers;
            } else {
                int count = 0;
                for (ResourceRecord nameServer : nameServers) {
                    System.out.println("GET TEXT RESULT " + nameServer.getTextResult());
                    System.out.println(count++);
                    DNSNode nameServerNode = new DNSNode(nameServer.getTextResult(), RecordType.getByCode(1));
                    Set<ResourceRecord> possibleRecords = getResults(nameServerNode, 0);
                    if (!possibleRecords.isEmpty()) {
                        AANameServers.addAll(possibleRecords);
                        return AANameServers;
                    }
                }
            }
        }
        return null;
    }

    private static String getNameFromRecord(int num, byte[] receiveBuffer) {
        String rName = "";
        while (true) {
            int length = (receiveBuffer[num] & 0xFF);
            num++; // go to next byte
            if (length == 0)
                break; // when 00
            else if (length == 192) { // 0xc0
                int newNum = (receiveBuffer[num] & 0xFF); // read offset
                num++;
                rName = rName + getNameFromRecord(newNum, receiveBuffer);
                break;
            } else {
                for (int i = 0; i < length; i++) {
                    rName = rName + (char) (receiveBuffer[num] & 0xff);
                    num++;
                }
                rName = rName + ".";
            }

        }
        if (rName.length() > 1 && rName.charAt(rName.length() - 1) == '.') {
            rName = rName.substring(0, rName.length() - 1);
        }
        cur = num;
        return rName;
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
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {

        if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }

        // TODO To be completed by the student

        InetAddress nameServer = rootServer; // setting up root server
        Set<ResourceRecord> cacheResults = cache.getCachedResults(node); // searching in cache

        if (!cacheResults.isEmpty()) {
            return cacheResults;
        }
        DNSNode cnameNode = new DNSNode(node.getHostName(), RecordType.getByCode(5)); //creating a CNAME record

        for (int i = 0; i < 30; i++) {
            System.out.println(i + "This is i");
            cacheResults = cache.getCachedResults(cnameNode);
            if (!cacheResults.isEmpty()) {
                System.out.println("CNAME CHECK");
                Set<ResourceRecord> possibleCNames = new HashSet<>();
                for (ResourceRecord r : cacheResults) {
                    possibleCNames.addAll(getResults(new DNSNode(r.getTextResult(), node.getType()), indirectionLevel + 1));
                }
                System.out.println("Possible cname record " + possibleCNames.size());
                return possibleCNames;
            } else {
                if (nameServer != null) {
                    System.out.println("AABB");
                    nameServer = getNextServer(nameServer, node); // next server to look into

                    cacheResults = cache.getCachedResults(node); // new server contents go into cache
                    if (!cacheResults.isEmpty()) {
                        System.out.println("IN CACHE");
                        return cacheResults;
                    }

                } else {
                    cacheResults = cache.getCachedResults(node);
                    if (!cacheResults.isEmpty()) {
                        return cacheResults;
                    }
                }

            }

        }
        return Collections.emptySet();
    }

    private static InetAddress getNextServer(InetAddress server, DNSNode node) {
        ByteArrayOutputStream bOutput = new ByteArrayOutputStream();
        DataOutputStream dOutput = new DataOutputStream(bOutput);
        DatagramPacket requestPacket = null;
        queryID = random.nextInt(65536); // range [0, 65535]

        while (!queryIDs.add(queryID)) {
            queryID = random.nextInt(65536);
        }

        try {
            // Write query packet
            dOutput.writeShort(queryID);
            dOutput.writeShort(0x0000); // query flags
            dOutput.writeShort(0x0001);
            dOutput.writeShort(0x0000);
            dOutput.writeShort(0x0000);
            dOutput.writeShort(0x0000);

            String[] parts = node.getHostName().split(("\\."));
            for (int i = 0; i < parts.length; i++) {
                byte[] partBytes = parts[i].getBytes("UTF-8");
                dOutput.writeByte(parts[i].length()); // specify length
                dOutput.write(partBytes);             // specify actual bytes
            }

            dOutput.writeByte(0x00); // ending byte
            int QType = node.getType().getCode();
            dOutput.writeShort((short) QType);
            dOutput.writeShort(0x0001);

            byte[] byteArray = bOutput.toByteArray();
            requestPacket = new DatagramPacket(byteArray, byteArray.length, server, DEFAULT_DNS_PORT);
            socket = new DatagramSocket();
            socket.setSoTimeout(5000);
            socket.send(requestPacket);

        } catch (Exception e) {

        }

        byte[] bufferReceive = new byte[1024];
        DatagramPacket receivePacket = new DatagramPacket(bufferReceive, bufferReceive.length);
        try {
            socket.receive(receivePacket);
        } catch (Exception e) {
            try {
                socket.send(requestPacket);
                socket.receive(receivePacket);
            } catch (Exception exception) {
                // TODO verbosePrint
                return null;
            }
        }

        ArrayList<ResourceRecord> nameServers = receiveDecode(bufferReceive);
        if (nameServers != null) { // not authoritative
            return nameServers.get(0).getInetResult();
        } else {
            return null;
        }
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
