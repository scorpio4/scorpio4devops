package com.scorpio4.curate.nms;

import com.scorpio4.fact.stream.FactStream;
import com.scorpio4.util.string.PrettyString;
import net.percederberg.mibble.*;
import net.percederberg.mibble.snmp.SnmpObjectType;
import net.percederberg.mibble.snmp.SnmpType;
import net.percederberg.mibble.type.IntegerType;
import net.percederberg.mibble.type.ObjectIdentifierType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.util.Calendar;
import java.util.Date;

/**
 * Scorpio4 (c) 2013-2014
 * Module: com.scorpio4.learn
 * User  : root
 * Date  : 11/14/13
 * Time  : 2:13 AM
 */
public class MIB2N3 {
    private static final Logger log = LoggerFactory.getLogger(MIB2N3.class);
    private static final String NS_MIB = "http://www.iana.org/assignments/mib/#";
    String VERSION = "0.1";
    MibLoader loader = new MibLoader();
    File dest_path = new File(".");
    String suffix = ".n3";
    String mibont = "-undefined-";
    PrintStream out = System.out;

    public MIB2N3() {
    }

    public MIB2N3(File file) throws IOException,MibLoaderException {
        load(file);
    }

    public void learn(FactStream learn) {

    }

    public void setDir(File path) {
        this.dest_path=path;
    }

    public String getSuffix() {
        return suffix;
    }

    public void setSuffix(String suff) {
        suffix=suff;
    }


    public void load(File file) throws IOException,MibLoaderException {
        if (!file.exists()) throw new FileNotFoundException("MIB file not found: "+file.getAbsolutePath());
        header();
        log.debug("Convert MIB: " + file.getAbsolutePath());
        Date today = new Date();
        Calendar calendar = Calendar.getInstance();
        write("# "+file.getName());
        write("# MIB2RDFS - v:"+VERSION+" - "+today);
        write("# ---------------------------------------------------------");
        loader.addDir(file.getParentFile());
        Mib mib = loader.load(file);
        walk(mib);
    }

    protected void walk(Mib mib) throws MibLoaderException {
        MibValueSymbol root = mib.getRootSymbol();
        mibont = mib.getName().toLowerCase();
        oid_uri(mibont,"a","mib:MIB");
        literal("rdfs:label", PrettyString.humanize(mib.getName()));
        literal("rdfs:comment",mib.getHeaderComment());
        literal("rdfs:comment",mib.getFooterComment());
        uri("mib:hasRoot",""+root.getValue());
        write(".");

        oid_uri(""+root.getValue(),"a","mib:ObjectIdentifier");
        literal("rdfs:label",PrettyString.humanize(root.getName()));

        write(".");
        if (root!=null) walk(null,null,root);
    }

    //getTag()
    protected void walk(MibValueSymbol group, MibValueSymbol parent, MibValueSymbol sym) throws MibLoaderException {
        if (sym==null) {
            System.err.println("ERROR: NULL symbol @ "+parent.getName());
            return;
        }
        MibType type = sym.getType();
        if (type==null) {
            System.err.println("ERROR: NULL type @ "+sym.getName());
            return;
        }

        if (parent!=null) {
            if (!(type instanceof ObjectIdentifierType) ) {
                write( null, parent, sym);
            } else {
                String pretty_type = PrettyString.camelCase(sym.getType().getName());
                oid_uri(""+sym.getValue(),"a","mib:"+pretty_type);
                literal("rdfs:label",PrettyString.humanize(sym.getName()));
                uri("mib:hasParent",parent.getValue());
                uri("owl:sameAs", getSymbolicPath(sym));

                group = sym;
                write(".");
            }
        }
//if (group!=null && group==sym) System.err.println("Group:"+group.getValue());
        for (int i=0;i<	sym.getChildCount() ;i++) walk(group,sym,sym.getChild(i));
    }

    protected void write(MibValueSymbol group, MibValueSymbol parent, MibValueSymbol sym) {
        MibType type = sym.getType();

        if (type instanceof SnmpType) {
            if (type instanceof SnmpObjectType) {
                write((SnmpObjectType)type, sym);
            } else {
                write(type, sym);
            }
        } else if (type instanceof ObjectIdentifierType) {
            write(type, sym);
        } else {
            write(type, sym);
        }

        if (parent!=null) {
            if (sym.getName().startsWith(parent.getName())) {
                literal("rdfs:label", PrettyString.humanize( sym.getName().substring(parent.getName().length())) );
            } else literal("rdfs:label", PrettyString.humanize(sym.getName()));
            uri("mib:hasParent",""+parent.getValue());
        } else {
            literal("rdfs:label",PrettyString.humanize(sym.getName()));
        }

        if (group!=null) uri("mib:hasGroup", group.getValue());
        write(".");
    }

// ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- -----

    // Write SimpleObject
    protected void write(MibType type, MibValueSymbol sym) {
        oid_uri(""+sym.getValue(),"a","mib:"+PrettyString.camelCase(type.getName()));
        uri("owl:sameAs", getSymbolicPath(sym));
        if (sym.getComment()!=null) literal("rdfs:comment",sym.getComment().replace('\n',' '));
        uri("mib:isDefinedBy", mibont);
    }

    // Write SnmpObjectType
    protected void write(SnmpObjectType stype, MibValueSymbol sym) {
        MibType syntax = stype.getSyntax();
        String pretty_type = PrettyString.camelCase(syntax.getName());

        // type hierarchy
        oid_uri(""+sym.getValue(),"a","mib:"+pretty_type);
        if (sym.isScalar()) fact("a","mib:Scalar");
        if (sym.isTable()) fact("a","mib:Table");
        if (sym.isTableColumn()) fact("a","mib:TableColumn");
        if (sym.isTableRow()) fact("a","mib:TableRow");

        uri("owl:sameAs",		getSymbolicPath(sym));

        uri("mib:hasAccess",	"access:"+stype.getAccess());
        uri("mib:hasStatus",	"status:"+stype.getStatus());

        literal("mib:default",	stype.getDefaultValue());
        literal("mib:units",	stype.getUnits());

        String desc = ((SnmpType)stype).getUnformattedDescription();
        literal("dc:description",(desc==null?"":desc.replaceAll("\\s+"," ")) );

        if (sym.getComment()!=null) literal("rdfs:comment",sym.getComment().replaceAll("\\s+"," "));
        uri("mib:isDefinedBy", mibont);

        if (syntax instanceof IntegerType) {
            IntegerType int_type = (IntegerType)syntax;
            MibValueSymbol[] syms = int_type.getAllSymbols();
            for(int i=0;i<syms.length;i++) {
//						literal("mib:value", syms[i]);
//TODO: emit property definitions
            }
        }
    }

// ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- -----

    protected File destination(File file) {
        System.err.println(">>"+file.getAbsolutePath()+"  --  "+dest_path.getAbsolutePath());
        if (file.getAbsolutePath().startsWith(dest_path.getAbsolutePath())) {
            return new File(dest_path, file.getAbsolutePath().substring(dest_path.getAbsolutePath().length()));
        }
        return file;
    }

    public void header() {
        write("@prefix dc:	<http://purl.org/dc/elements/1.1/> .");
        write("@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .");
        write("@prefix owl: <http://www.w3.org/2002/07/owl#> .");
        write("@prefix mib: <"+ NS_MIB +"> .");


    }

    public void write(String str) {
        out.println(str);
    }

    public void literal(String name, Object value) {
        if (value==null) return;
        write("\t"+name+"\t\""+value.toString().replace('\"','\'')+"\";");
    }

    public void uri(String name, Object uri) {
        if (uri==null) return;
        write("\t"+name+"\t<"+OIDtoURI(uri.toString())+">;");
    }

    public void fact(String name, Object value) {
        write("\t"+name+"\t"+value.toString()+";");
    }

    public void oid_uri(String subj, String pred, String obj) {
        write("<"+OIDtoURI(subj)+"> "+pred+" "+obj+";");
    }

    public static String OIDtoURI(String oid) {
        if(oid.endsWith(":")) return NS_MIB +oid.substring(0,oid.length()-1);
        else return NS_MIB +oid;
    }


    public String getSymbolicPath(MibValueSymbol sym) {
        StringBuffer path = new StringBuffer();
        symbolicPath(path,sym);
        return path.toString();
    }

    private void symbolicPath(StringBuffer path, MibValueSymbol sym) {
        if (path.length()==0) path.insert(0,sym.getName());
        else path.insert(0,":"+sym.getName());
        if (sym.getParent()!=null) symbolicPath(path, sym.getParent());
    }
}
