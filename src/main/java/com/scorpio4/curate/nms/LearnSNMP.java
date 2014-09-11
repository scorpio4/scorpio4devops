package com.scorpio4.curate.nms;

/* ****************************************************************************************

	Scorpio4 (c) Lee Curtis 2009-2012. All rights reserved.
	Architect:	Lee Curtis
	Developer:	Troven Software

***************************************************************************************** */

import com.scorpio4.fact.stream.FactStream;
import com.scorpio4.oops.FactException;
import org.limewire.collection.Trie;
import org.openrdf.repository.RepositoryException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.westhawk.snmp.pdu.OneGetNextPdu;
import uk.co.westhawk.snmp.stack.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Observable;
import java.util.Observer;

/** LearnSNMP returns a RDF/XML tools describing the result of an SNMP query.

	for a vector, we GET-NEXT over the tree:
		http://localhost/snmpv2/community@127.0.0.1:160/1/3/6/1/2/1/2/2/
	for a scalar, we GET the oid:
		http://localhost/snmpv2/community@127.0.0.1:160/1/3/6/1/2/1/1/1

**/

public class LearnSNMP implements Runnable {
    private static final Logger log = LoggerFactory.getLogger(LearnSNMP.class);

    public static final String NS_IPv4 = NMSVOCAB.NS_IPv4;
    public static final String NS_MIB = NMSVOCAB.NS_MIB;

    FactStream learn = null;
    Trie oids = null;
    Map config = new HashMap();
    Map walkers = new HashMap();

    // online API at http://kellernet.dk/datamatiker/.obdata/net/snmp/WestHawk/javadoc/index.html
	protected SnmpContextv2cPool snmp_ctx = null;

    public LearnSNMP(String host, int port, String community) throws IOException, RepositoryException {
        SnmpContextv2cPool snmp = new SnmpContextv2cPool(host,port);
        snmp.setCommunity(community);
        init(snmp);
    }

	public LearnSNMP(SnmpContextv2cPool snmp_ctx, String org_oid) throws PduException, IOException, RepositoryException {
        init(snmp_ctx);
        walk(org_oid);
	}

    public void init(SnmpContextv2cPool snmp_ctx) throws RepositoryException {
        this.snmp_ctx=snmp_ctx;
    }

    public void setOIDS(Trie oids) {
        this.oids=oids;
    }
    public void learn(FactStream learn) {
        this.learn=learn;
    }

    public void configure(Map config) {
        this.config=config;
    }

    public Map getConfiguration() {
        return config;
    }

    public void start() {
    }

    public void stop(){
        snmp_ctx.destroy();
    }

    public boolean isRunning() {
        return snmp_ctx!=null && !walkers.isEmpty();
    }

    public String getIdentity() {
        return snmp_ctx.getHost()+":"+snmp_ctx.getPort();
    }


    public void walk(String org_oid) {
        try {
            SNMPWalker walker = new SNMPWalker(this,org_oid);
            walkers.put(walker, System.currentTimeMillis());
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PduException e) {
            e.printStackTrace();  
        }
    }

    @Override
    public void run() {
        try {
            if (!isRunning()) start();
            log.debug("LearnSNMP running");
            while(isRunning()) {
                Thread.yield();
            }
            stop();
            log.debug("LearnSNMP finished");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class SNMPWalker implements Observer {
    private static final Logger log = LoggerFactory.getLogger(SNMPWalker.class);
    LearnSNMP snmp;
    String org_oid;

    public SNMPWalker(LearnSNMP snmp, String oid) throws IOException, PduException {
        this.snmp=snmp;
        walk(oid);
    }

    public void done() {
        snmp.walkers.remove(this);
    }

    public void walk(String oid) throws uk.co.westhawk.snmp.stack.PduException, IOException {
        this.org_oid =oid;
        rewalk(oid);
    }

    public void rewalk(String oid) throws uk.co.westhawk.snmp.stack.PduException, IOException {
        Pdu pdu = new OneGetNextPdu(snmp.snmp_ctx);
        pdu.addOid(new varbind(oid));
        pdu.addObserver(this);
//        log.debug("Sending PDU: " + pdu.toString());
        pdu.send();
    }

    public void walk(String[] oids) throws uk.co.westhawk.snmp.stack.PduException, IOException {
        if (oids.length<1) return;
        Pdu pdu = new OneGetNextPdu(snmp.snmp_ctx);
        for(int i=0;i<oids.length;i++) pdu.addOid(oids[i]);
        pdu.addObserver(this);
//        log.debug("Sending "+oids.length+" PDU: " + pdu.toString());
        pdu.send();
    }


    @Override
    public void update(Observable obs, Object varbs) {
        Pdu pdu = (Pdu)obs;
//        log.debug("Received PDU: "+pdu.getErrorStatus()+" -> "+pdu.toString());

// These errors are usually transient and we'll re-run the collection rather than handle errors gracefully.

	    if (pdu.getErrorStatus() == AsnObject.SNMP_ERR_GENERR) {
            log.debug("SNMP_ERR_GENERR: "+pdu.getErrorStatus()+" -> "+pdu+" ==> "+varbs);
            done();
            return;
        } else if (pdu.getErrorStatus() != AsnObject.SNMP_ERR_NOERROR) {
            log.debug("SNMP_ERR_NOERROR: "+pdu.getErrorStatus()+" -> "+pdu+" ==> "+varbs);
            done();
            return;
        }

// decode our result (varbind)
        varbind vars = (varbind) varbs;
        AsnObject asn_obj = vars.getValue();
        if (asn_obj.getRespType() == AsnObject.SNMP_VAR_ENDOFMIBVIEW) {
            log.debug("SNMP_VAR_ENDOFMIBVIEW: "+pdu.getErrorStatus()+" -> "+pdu);
            done();
            return;
        }
//decode our PDU
        try {
//            varbind[] reqVars = pdu.getRequestVarbinds();

            varbind[] resVars = pdu.getResponseVarbinds();

            String hostURI = snmp.NS_IPv4+pdu.getContext().getHost();
            for(int i=0;i<resVars.length;i++) {
                // walk each response, if still relevant
                String new_oid = resVars[i].getOid().toString();
                if (new_oid.startsWith(org_oid)) {
                    log.debug("Res #" + i + ": " + resVars[i] + " (" + resVars[i].getValue().getClass().getCanonicalName() + ")");
                    learn(hostURI, new_oid, resVars[i]);
                    rewalk(new_oid);
                } else {
                    log.trace("Skipped: "+new_oid);
                }
            }

        } catch(uk.co.westhawk.snmp.stack.PduException e) {
            log.error("PduException: "+e.getMessage(),e);
        } catch(IOException e) {
            log.error("IOException: "+e.getMessage(),e);
        } catch (FactException e) {
            log.error("FactException: "+e.getMessage(),e);
        }
    }

    protected void learn(String hostURI, String oid, varbind varb) throws FactException {
        if (snmp.learn!=null) {
            int last_octet_ix = oid.lastIndexOf(".");
            String oidURI = snmp.NS_MIB+oid.substring(0, last_octet_ix);

            if (snmp.oids!=null) {
                // use explicit URI mapping
                Map trie_oid = (Map)snmp.oids.select(snmp.NS_MIB+oid);
                if (trie_oid!=null) {
                    oidURI = (String)trie_oid.get("this");
                }
            }
            if (oidURI==null) {
                // use implicit URI mapping
                log.warn("Unknown OID: " + oid);
                return;
            }

            AsnObject value = varb.getValue();
            if (value instanceof AsnObjectId) {
                snmp.learn.fact(hostURI, oidURI, snmp.NS_MIB+varb.getValue());
            } else if (value instanceof AsnInteger || value instanceof  AsnUnsInteger || value instanceof  AsnUnsInteger64) {
                snmp.learn.fact(hostURI, oidURI, varb.getValue(), "integer");
            } else {
                snmp.learn.fact(hostURI, oidURI, varb.getValue(), "string");
            }
        }
    }
}