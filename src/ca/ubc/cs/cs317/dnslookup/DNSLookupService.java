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
    private static InetAddress nextServer;
    private static boolean endCondition = false;

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
     * Decode the resource record from byteBuffer
     *
     * @param receiveBuffer
     * @return decoded ResourceRecord
     */
    private static ResourceRecord decodeResourceRecord(byte[] receiveBuffer) {
        String recordName = getNameFromResourceRecord(cur, receiveBuffer);
        int typeVal = ((receiveBuffer[cur++] & 0xFF) << 8) + (receiveBuffer[cur++] & 0xFF);
        int classVal = ((receiveBuffer[cur++] & 0xFF) << 8) + (receiveBuffer[cur++] & 0xFF);
        long TTL = ((receiveBuffer[cur++] & 0xFF) << 24) + ((receiveBuffer[cur++] & 0xFF) << 16) + ((receiveBuffer[cur++] & 0xFF) << 8) + (receiveBuffer[cur++] & 0xFF);
        int RDATALen = ((receiveBuffer[cur++] & 0xFF) << 8) + (receiveBuffer[cur++] & 0xFF);
        ResourceRecord record;

        String ipAddress = "";
        switch (typeVal) {
            case 1: // Type A
                for (int i = 0; i < RDATALen; i++) {
                    ipAddress = ipAddress + (receiveBuffer[cur++] & 0xff) + ".";
                }
                ipAddress = ipAddress.substring(0, ipAddress.length() - 1);
                try {
                    record = new ResourceRecord(recordName, RecordType.getByCode(typeVal), TTL, InetAddress.getByName(ipAddress));
                } catch (Exception e) {
                    record = null;
                }
                break;
            case 2: // Type NS
            case 5: // Type CNAME
                String name = getNameFromResourceRecord(cur, receiveBuffer);
                record = new ResourceRecord(recordName, RecordType.getByCode(typeVal), TTL, name);
                break;
            case 28: // Type AAAA IPv6
                for (int i = 0; i < RDATALen / 2; i++) { // 8 octets, length 16
                    ipAddress = ipAddress +
                            Integer.toHexString(((receiveBuffer[cur++] & 0xFF) << 8) + (receiveBuffer[cur++] & 0xFF))
                            + ":";
                }
                ipAddress = ipAddress.substring(0, ipAddress.length() - 1);
                try {
                    record = new ResourceRecord(recordName, RecordType.getByCode(typeVal), TTL, InetAddress.getByName(ipAddress));
                } catch (Exception e) {
                    record = null;
                }
                break;
            default:
                String defaultName = getNameFromResourceRecord(cur, receiveBuffer);
                record = new ResourceRecord(recordName, RecordType.getByCode(typeVal), TTL, defaultName);
                break;
        }
        verbosePrintResourceRecord(record, typeVal);

        return record;
    }

    /**
     * Decode server response to query
     *
     * @param receiveBuffer
     * @return list of decoded ResourceRecords from server response
     */
    private static List<ResourceRecord> decodeServerResponse(byte[] receiveBuffer) {
        int receiveID = ((receiveBuffer[0] & 0xFF) << 8) + (receiveBuffer[1] & 0xFF);
        if (queryID != receiveID) {
            return null;
        }

        int AA = (receiveBuffer[2] & 0x04) >>> 2;
        boolean isAuthoritativeServer = AA == 1;
        int RCODE = receiveBuffer[3] & 0x0F;
        if (verboseTracing) {
            System.out.println("Response ID:" + " " + receiveID + " " + "Authoritative" + " " + "=" + " " + isAuthoritativeServer);
        }

        int QCOUNT = ((receiveBuffer[4] & 0xFF) << 8) + (receiveBuffer[5] & 0xFF);
        int ANSCOUNT = ((receiveBuffer[6] & 0xFF) << 8) + (receiveBuffer[7] & 0xFF);
        int AUTHORITYCOUNT = ((receiveBuffer[8] & 0xFF) << 8) + (receiveBuffer[9] & 0xFF);
        int ADDCOUNT = ((receiveBuffer[10] & 0xFF) << 8) + (receiveBuffer[11] & 0xFF);


        cur = 12; // starting from Question section 12 byte
        String qName = "";
        int flag = 0;
        while (flag == 0) {
            int length = (receiveBuffer[cur] & 0xFF);
            cur++; // go to next byte
            if (length == 0) {
                break; // when 00
            }
            for (int i = 0; i < length; i++) {
                qName = qName + (char) (receiveBuffer[cur] & 0xff);
                cur++;
            }
            qName = qName + ".";
        }

        int qTYPE = ((receiveBuffer[cur++] & 0xFF) << 8) + (receiveBuffer[cur++] & 0xFF);
        int QCLASS = ((receiveBuffer[cur++] & 0xFF) << 8) + (receiveBuffer[cur++] & 0xFF);

        if (verboseTracing) {
            System.out.printf("  " + "Answers" + " " + "(%d)" + "\n", ANSCOUNT);
        }
        List<ResourceRecord> answers = decodeRecordsToList(receiveBuffer, ANSCOUNT);
        if (verboseTracing) {
            System.out.printf("  " + "Nameservers" + " " + "(%d)" + "\n", AUTHORITYCOUNT);
        }
        List<ResourceRecord> nameServers = decodeRecordsToList(receiveBuffer, AUTHORITYCOUNT);
        if (verboseTracing) {
            System.out.printf("  " + "Additional Information" + " " + "(%d)" + "\n", ADDCOUNT);
        }
        List<ResourceRecord> additionalServers = decodeRecordsToList(receiveBuffer, ADDCOUNT);

        // if only SOA record is found
        if (nameServers.size() == 1 && nameServers.get(0).getType() == RecordType.SOA) {
            endCondition = true;
        }

        if ((!isAuthoritativeServer || ANSCOUNT != 0) && RCODE == 0) {
            return matchAuthoritativeServerToAdditional(nameServers, additionalServers);
        }

        return null;
    }

    /**
     * Decode and cache resource records from byteBuffer
     *
     * @param receiveBuffer
     * @param count         ANSCOUNT, AUTHORITYCOUNT, ADDCOUNT
     * @return list of valid ResourceRecords
     */
    private static List<ResourceRecord> decodeRecordsToList(byte[] receiveBuffer, int count) {
        List<ResourceRecord> list = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            ResourceRecord resourceRecord = decodeResourceRecord(receiveBuffer);
            if (resourceRecord != null) {
                list.add(resourceRecord);
                cache.addResult(resourceRecord);
            }
        }
        return list;
    }

    /**
     * Matches authoritative server name to IP address from additional part,
     * gets authoritative server IP address if not in additional part
     *
     * @param nameServers
     * @param additionalServers
     * @return list of ResourceRecord for authoritative servers with known IP address
     */
    private static List<ResourceRecord> matchAuthoritativeServerToAdditional(List<ResourceRecord> nameServers,
                                                                             List<ResourceRecord> additionalServers) {
        List<ResourceRecord> AANameServers = new ArrayList<>();
        // Look for IP address of Authoritative server in Additional
        for (ResourceRecord nameServer : nameServers) {
            for (ResourceRecord additionalServer : additionalServers) {
                if (additionalServer.getTextResult().equals(nameServer.getTextResult()) &&
                        additionalServer.getType().getCode() == 1) {
                    AANameServers.add(additionalServer);
                }
            }
        }
        // If IP address was found, return Authoritative servers
        if (!AANameServers.isEmpty()) {
            return AANameServers;
        }

        // Otherwise getResults using Authoritative server then return Authoritative servers
        for (ResourceRecord nameServer : nameServers) {
            DNSNode nameServerNode = new DNSNode(nameServer.getTextResult(), RecordType.A);
            Set<ResourceRecord> possibleRecords = getResults(nameServerNode, 0);
            if (!possibleRecords.isEmpty()) {
                AANameServers.addAll(possibleRecords);
                return AANameServers;
            }
        }

        return null;
    }

    private static String getNameFromResourceRecord(int num, byte[] receiveBuffer) {
        String rName = "";
        int flag = 0;
        while (flag == 0) { // loop until ending byte 00 is hit
            int length = (receiveBuffer[num] & 0xFF);
            num++; // go to next byte
            if (length == 0) {
                break; // when 00
            } else if (length >= 192) { // 0xc0
                int newNum = (length - 192) * 256 + (receiveBuffer[num] & 0xFF); // read offset
                num++;
                rName = rName.concat(getNameFromResourceRecord(newNum, receiveBuffer));
                break;
            } else {
                for (int i = 0; i < length; i++) {
                    rName = rName + (char) (receiveBuffer[num] & 0xff);
                    num++;
                }
                rName = rName.concat(".");
            }

        }
        if (rName.length() > 0 && rName.charAt(rName.length() - 1) == '.') {
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

        InetAddress nameServer = rootServer; // setting up root server
        Set<ResourceRecord> cacheResults = cache.getCachedResults(node); // searching in cache
        if (!cacheResults.isEmpty()) {
            return cacheResults;
        }

        DNSNode cnameNode = new DNSNode(node.getHostName(), RecordType.CNAME); //creating a CNAME record

        while (true) {
            cacheResults = cache.getCachedResults(cnameNode);
            if (!cacheResults.isEmpty()) {
                Set<ResourceRecord> possibleCNames = new HashSet<>();
                for (ResourceRecord r : cacheResults) {
                    possibleCNames.addAll(getResults(new DNSNode(r.getTextResult(), node.getType()), indirectionLevel + 1));
                }

                return possibleCNames;
            } else {
                if (nameServer != null) {
                    retrieveResultsFromServer(node, nameServer); // next server to look into
                    nameServer = nextServer;
                }

                if (endCondition) {
                    endCondition = false;
                    break;
                }

                cacheResults = cache.getCachedResults(node); // new server contents go into cache
                if (!cacheResults.isEmpty()) {
                    return cacheResults;
                }
            }
        }

        return Collections.emptySet();
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
        ByteArrayOutputStream bOutput = new ByteArrayOutputStream();
        DataOutputStream dOutput = new DataOutputStream(bOutput);
        DatagramPacket requestPacket;
        queryID = random.nextInt(65536); // range [0, 65535]

        // Ensures unique query ID
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
            for (String part : parts) {
                byte[] partBytes = part.getBytes("UTF-8");
                dOutput.writeByte(part.length());  // specify length
                dOutput.write(partBytes);          // specify actual bytes
            }

            dOutput.writeByte(0x00); // ending byte
            int QType = node.getType().getCode();
            dOutput.writeShort((short) QType);
            dOutput.writeShort(0x0001);

            byte[] byteArray = bOutput.toByteArray();
            requestPacket = new DatagramPacket(byteArray, byteArray.length, server, DEFAULT_DNS_PORT);
            socket = new DatagramSocket();
            socket.setSoTimeout(5000);
            if (verboseTracing) {
                System.out.println();
                System.out.println();
                System.out.println("Query ID" + "     " + queryID + " " + node.getHostName() + "  " +
                        node.getType() + " " + "-->" + " " + server.getHostAddress());
            }
            socket.send(requestPacket);
        } catch (Exception e) {
            return;
        }

        byte[] bufferReceive = new byte[1024];
        DatagramPacket receivePacket = new DatagramPacket(bufferReceive, bufferReceive.length);
        try {
            socket.receive(receivePacket);
        } catch (SocketTimeoutException e) {
            try {
                if (verboseTracing) {
                    System.out.println();
                    System.out.println();
                    System.out.println("Query ID" + "     " + queryID + " " + node.getHostName() + "  " +
                            node.getType() + " " + "-->" + " " + server.getHostAddress());
                }
                socket.send(requestPacket);
                socket.receive(receivePacket);
            } catch (Exception exception) {
                return;
            }
        } catch (Exception e) {
            return;
        }

        List<ResourceRecord> nameServers = decodeServerResponse(bufferReceive);
        nextServer = nameServers != null ? nameServers.get(0).getInetResult() : null;
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

