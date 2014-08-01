package com.scorpio4.curate.nms;

import com.scorpio4.fact.stream.FactStream;
import com.scorpio4.oops.FactException;
import com.scorpio4.util.DateXSD;
import com.scorpio4.util.string.PrettyString;
import com.scorpio4.vocab.COMMONS;
import net.percederberg.mibble.*;
import net.percederberg.mibble.snmp.*;
import net.percederberg.mibble.type.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.NoSuchElementException;

/**
 *
 * Scorpio4 (c) 2013-2014
 * Module: com.scorpio4.learn
 * User  : lee
 * Date  : 18/11/2013
 * Time  : 6:52 PM
 *
 */

public class LearnMIB {
	private static final Logger log = LoggerFactory.getLogger(LearnMIB.class);
	public static String NS_MIB = "http://scorpio4.com/v1/nms/";

	MibLoader loader = new MibLoader();
	FactStream learn = null;
	DateXSD dateXSD = new DateXSD();

	public LearnMIB() {
	}

	public LearnMIB(FactStream learn) {
		learn(learn);
	}

	public void learn(FactStream learn) {
		this.learn = learn;
	}

	public void learn(File mibFile) throws IOException, MibLoaderException, FactException {
		learn(mibFile, learn);
	}

	public void learn(File mibFile, FactStream learn) throws IOException, MibLoaderException, FactException {
		if (mibFile.isDirectory()) {
			log.debug("Load MIB Directory: "+mibFile.getAbsolutePath());
			loader.addDir(mibFile);
			File file[] = mibFile.listFiles();
			for(int i=0;i<file.length;i++) {
				learn(file[i], learn);
			}
		} else {
			try {
				log.debug("Load MIB File: "+mibFile.getAbsolutePath());
				loader.addDir(mibFile.getParentFile());
				Mib mib = loader.load(mibFile);
				learn(mib, learn);
			} catch(MibLoaderException e) {
				log.error("MIB Failed: "+mibFile.getAbsolutePath());
			}
		}
	}

	public void learn(Mib mib, FactStream learn) throws FactException, MibLoaderException {
		MibValueSymbol root = mib.getRootSymbol();
		if (root==null) {
			Collection symbols = mib.getAllSymbols();
			for(Object symbol:symbols) {
				if (symbol instanceof MibMacroSymbol)
					learn( (MibMacroSymbol) symbol, learn);
				else if (symbol instanceof MibTypeSymbol)
					learn( (MibTypeSymbol) symbol, learn);
				else
					log.debug("ROOT SYMBOL:"+symbol.getClass().getCanonicalName());
			}
			return;
		}

		String label = PrettyString.pretty(mib.getName());
		String hComment = mib.getHeaderComment();
		String fComment = mib.getFooterComment();
		String mibURI = NS_MIB+root.getValue();

		String comment = comments((hComment==null?"":hComment)+(fComment==null?"":fComment)+label);

		learn.fact(mibURI, COMMONS.A , NS_MIB+"MIB");
		learn.fact(mibURI, COMMONS.SAMEAS, NS_MIB+getSymbolicPath(root));

		learn.fact(mibURI, COMMONS.LABEL, label, "string");
		learn.fact(mibURI, COMMONS.COMMENT, comment, "string");

		if (root.getType() instanceof SnmpModuleIdentity)
			learn( (SnmpModuleIdentity) root.getType(), root, learn);

		for (int i=0;i<root.getChildCount() ;i++) {
			learn(root.getChild(i), learn);
		}
	}

	protected void learn(MibValueSymbol sym, FactStream learn) throws MibLoaderException, FactException {
		if (sym==null) {
			log.error("Missing Value: "+sym);
//            throw new FactException("urn:scorpio4:learn:mib:oops:missing-mib-value#"+group.getValue());
			return;
		}
		MibType type = sym.getType();
		if (type!=null) {
			if (type instanceof SnmpObjectType) {
				learn( (SnmpObjectType)type, sym, learn);
			} else if (type instanceof ObjectIdentifierType) {
				learn( (ObjectIdentifierType)type, sym, learn);
			} else if (type instanceof SnmpObjectIdentity) {
				learn( (SnmpObjectIdentity)type, sym, learn);
			} else if (type instanceof SnmpModuleCompliance) {
				learn( (SnmpModuleCompliance)type, sym, learn);
			} else if (type instanceof SnmpObjectGroup) {
				learn( (SnmpObjectGroup)type, sym, learn);
			} else if (type instanceof SnmpModuleIdentity) {
				learn( (SnmpModuleIdentity)type, sym, learn);
			} else if (type instanceof SnmpNotificationGroup) {
				learn( (SnmpNotificationGroup)type, sym, learn);
			} else {
				log.error("Unknown Type: "+type+" -> "+type.getClass().getCanonicalName());
			}
//SnmpNotificationGroup
//            throw new FactException("urn:scorpio4:learn:mib:oops:missing-mib-type");
		} else {
			log.error("Missing Type for: "+sym);
		}

		for (int i=0;i<sym.getChildCount() ;i++) {
			learn(sym.getChild(i), learn);
		}
	}

	protected void learn(MibMacroSymbol sym, FactStream learn) throws MibLoaderException, FactException {
		String mibURI = NS_MIB+sym.getName();
		learn.fact(mibURI, COMMONS.A, NS_MIB + "Macro");
	}

	private void learn(MibTypeSymbol sym, FactStream learn) throws FactException {
		String mibURI = NS_MIB+sym.getName();
		learn.fact(mibURI, COMMONS.A, NS_MIB + "MibType");
	}

	private void learn(SnmpNotificationGroup type, MibValueSymbol sym, FactStream learn) {
		String mibURI = NS_MIB+sym.getValue();
//        type.getNotifications();
	}

	private void learn(SnmpObjectGroup type, MibValueSymbol sym, FactStream learn) throws FactException {
		String mibURI = NS_MIB+sym.getValue();
		String parentURI = NS_MIB+sym.getParent().getValue();
		learn.fact(parentURI, NS_MIB+"contains", mibURI);

		learn.fact(mibURI, COMMONS.A, NS_MIB + "SnmpObjectGroup");
		List objects = type.getObjects();
		for(int i=0;i<objects.size();i++) {
			learn.fact(mibURI, NS_MIB + "group", NS_MIB + objects.get(i).toString());
		}
	}

	private void learn(SnmpModuleCompliance type, MibValueSymbol sym, FactStream learn) throws FactException {
		String mibURI = NS_MIB+sym.getValue();
		String parentURI = NS_MIB+sym.getParent().getValue();
		learn.fact(parentURI, NS_MIB+"contains", mibURI);
		log.debug("SnmpModuleCompliance: "+mibURI);
		learn.fact(mibURI, COMMONS.A, NS_MIB + "SnmpModuleCompliance");
		List objects = type.getModules();
		for(int i=0;i<objects.size();i++) {
			learn.fact(mibURI, NS_MIB + "module", NS_MIB + objects.get(i).toString());
		}
	}

	private void learn(SnmpObjectIdentity type, MibValueSymbol sym, FactStream learn) throws FactException {
		String mibURI = NS_MIB+sym.getValue();
		String parentURI = NS_MIB+sym.getParent().getValue();
		learn.fact(parentURI, NS_MIB+"contains", mibURI);
		log.debug("SnmpObjectIdentity: "+mibURI+" -> "+type);
		learn.fact(mibURI, COMMONS.A, NS_MIB + "SnmpObjectIdentity");
	}

	protected void learn(SnmpModuleIdentity type, MibValueSymbol sym, FactStream learn) throws FactException {
		String mibURI = NS_MIB+sym.getValue();

		String comment = comments(type.getDescription());
		learn.fact(mibURI, COMMONS.COMMENT, comment, "string");
		learn.fact(mibURI, COMMONS.DC+"description", type.getDescription(), "string");

		learn.fact(mibURI, NS_MIB+"contactInfo", type.getContactInfo(), "string");
//        learn.fact(mibURI, NS_MIB+"name", type.getName(), "string");
		learn.fact(mibURI, NS_MIB+"organization", type.getOrganization(), "string");
		learn.fact(mibURI, NS_MIB+"revisions", type.getRevisions(), "string");
		learn.fact(mibURI, NS_MIB+"lastUpdated", type.getLastUpdated(), "string");

	}

	protected void learn(ObjectIdentifierType otype, MibValueSymbol sym, FactStream learn) throws FactException {
		String mibURI = NS_MIB+sym.getValue();
		String parentURI = NS_MIB+sym.getParent().getValue();
		learn.fact(parentURI, NS_MIB+"contains", mibURI);

		String pretty_type = PrettyString.camelCase( sym.getType().getName() );
		String label = PrettyString.humanize(sym.getName());
		String comment = sym.getComment();
		comment = comments(comment==null?label+" ["+otype.getName()+"]":comment);

		learn.fact(mibURI, COMMONS.A, NS_MIB+pretty_type);
		learn.fact(mibURI, COMMONS.SAMEAS, NS_MIB+getSymbolicPath(sym));

		learn.fact(mibURI, COMMONS.LABEL, label, "string");
		learn.fact(mibURI, COMMONS.COMMENT, comment, "string");
	}


	protected void learn(SnmpObjectType stype, MibValueSymbol sym, FactStream learn) throws FactException {
		MibType syntax = stype.getSyntax();
		String symURI = NS_MIB+sym.getValue();
		String parentURI = NS_MIB+sym.getParent().getValue();
		learn.fact(parentURI, NS_MIB+"contains", symURI);

		String pretty_type = PrettyString.camelCase(syntax.getName());

		// type hierarchy
		learn.fact(symURI,COMMONS.A,NS_MIB+pretty_type);
		if (sym.isScalar()) learn.fact(symURI, COMMONS.A, NS_MIB+"Scalar");
		if (sym.isTable()) learn.fact(symURI, COMMONS.A, NS_MIB+"Table");
		if (sym.isTableColumn()) learn.fact(symURI, COMMONS.A, NS_MIB+"TableColumn");
		if (sym.isTableRow()) learn.fact(symURI, COMMONS.A, NS_MIB+"TableRow");

		String label = PrettyString.humanize(sym.getName());
		String comment = comments(sym.getComment()==null?stype.getUnformattedDescription():sym.getComment());

		learn.fact(symURI, COMMONS.LABEL, label, "string" );
		learn.fact(symURI, COMMONS.COMMENT, comment, "string" );
		learn.fact(symURI, COMMONS.SAMEAS, NS_MIB+getSymbolicPath(sym));

		learn.fact(symURI, NS_MIB+"access", NS_MIB+"access:" + stype.getAccess());
		learn.fact(symURI, NS_MIB+"status", NS_MIB+"status:" + stype.getStatus());

		learn.fact(symURI, NS_MIB+"default", stype.getDefaultValue(), "string");
		learn.fact(symURI, NS_MIB+"units", stype.getUnits(), "string");

		learn(sym, syntax, learn);
	}

	private void learn(MibValueSymbol symbol, MibType syntax, FactStream learn) throws FactException {
		if (syntax instanceof IntegerType) learn( symbol, (IntegerType)syntax, learn);
		else if (syntax instanceof StringType) learn( symbol, (StringType)syntax, learn);
		else if (syntax instanceof SequenceType) learn( symbol, (SequenceType)syntax, learn);
		else if (syntax instanceof SequenceOfType) learn( symbol, (SequenceOfType)syntax, learn);
		else if (syntax instanceof ChoiceType) learn( symbol, (ChoiceType)syntax, learn);
		else log.error("Unknown Syntax: "+syntax.getName()+"-->"+syntax.getClass().getCanonicalName());
	}

	private void learn(MibValueSymbol sym, SequenceType type, FactStream learn) throws FactException {
		String symURI = NS_MIB+"syntax:"+sym.getValue();
		ElementType[] allSymbols = type.getAllElements();
		if(allSymbols.length==0) {
			String prettyType = PrettyString.camelCase(type.getName());
			learn.fact(NS_MIB+sym.getValue(), NS_MIB+"syntax", NS_MIB+prettyType);
			learn.fact(NS_MIB+prettyType, COMMONS.A, NS_MIB+"SequenceType");
			return;
		}
		learn.fact(NS_MIB+sym.getValue(), NS_MIB+"syntax", symURI);
		learn.fact(symURI, COMMONS.A, NS_MIB+"SequenceType");
		for(int i=0;i<allSymbols.length;i++) {
			ElementType symValue = allSymbols[i];
			String valueURI = symURI+":"+symValue.getName();
			learn.fact(valueURI, COMMONS.A, symURI);
			String label = symValue.getName();
			learn.fact(valueURI, COMMONS.LABEL, label, "string");
		}
	}

	private void learn(MibValueSymbol sym, SequenceOfType type, FactStream learn) throws FactException {
		String symURI = NS_MIB+"syntax:"+sym.getValue();
		log.debug("SequenceOfType:"+type.getName()+" -> "+type.getElementType()+" ["+type.getConstraint());
//        learn.fact(symURI, COMMONS.A, type.getElementType().getName(), "string");
	}

	private void learn(MibValueSymbol sym, ChoiceType type, FactStream learn) throws FactException {
		String symURI = NS_MIB+"syntax:"+sym.getValue();
		ElementType[] allSymbols = type.getAllElements();
		if(allSymbols.length==0) {
			String prettyType = PrettyString.camelCase(type.getName());
			learn.fact(NS_MIB+sym.getValue(), NS_MIB+"syntax", NS_MIB+prettyType);
			learn.fact(NS_MIB+prettyType, COMMONS.A, NS_MIB+"ChoiceType");
			return;
		}
		learn.fact(NS_MIB+sym.getValue(), NS_MIB+"syntax", symURI);
		learn.fact(symURI, COMMONS.A, NS_MIB+"ChoiceType");
		for(int i=0;i<allSymbols.length;i++) {
			ElementType symValue = allSymbols[i];
			String valueURI = symURI+":"+symValue.getName();
			learn.fact(valueURI, COMMONS.A, symURI);
			String label = symValue.getName();
			learn.fact(valueURI, COMMONS.LABEL, label, "string");
		}
	}

	private void learn(MibValueSymbol sym, ObjectIdentifierType type, FactStream learn) throws FactException {
//        log.error("ObjectIdentifierType: "+type.getName());
		String symURI = NS_MIB+"syntax:"+sym.getValue();
		String prettyType = PrettyString.camelCase(type.getName());
		learn.fact(NS_MIB+sym.getValue(), NS_MIB+"syntax", NS_MIB+prettyType);
		learn.fact(NS_MIB + prettyType, COMMONS.A, NS_MIB + "ObjectIdentifierType");
		return;
	}

	private void learn(MibValueSymbol sym, IntegerType type, FactStream learn) throws FactException {
		String symURI = NS_MIB+"syntax:"+sym.getValue();
		MibValueSymbol[] allSymbols = type.getAllSymbols();
		if(allSymbols.length==0) {
			String prettyType = PrettyString.camelCase(type.getName());
			learn.fact(NS_MIB+sym.getValue(), NS_MIB+"syntax", NS_MIB+prettyType);
			learn.fact(NS_MIB+prettyType, COMMONS.A, NS_MIB+"ObjectIdentifierType");
			return;
		}
		learn.fact(NS_MIB+sym.getValue(), NS_MIB+"syntax", symURI);
		learn.fact(symURI, COMMONS.A, NS_MIB+"ObjectIdentifierType");
		for(int i=0;i<allSymbols.length;i++) {
			MibValueSymbol symValue = allSymbols[i];
			String valueURI = symURI+":"+symValue.getValue();
			learn.fact(valueURI, COMMONS.A, symURI);
			String label = symValue.getName();
			String comment = symValue.getComment();
			comment = comments(comment==null||comment.equals("")?label:comment);
			learn.fact(valueURI, COMMONS.LABEL, label, "string");
			learn.fact(valueURI, COMMONS.COMMENT, comment, "string");
		}
	}

	private void learn(MibValueSymbol sym, StringType type, FactStream learn) throws FactException {
		String symURI = NS_MIB+sym.getValue();
		String prettyType = PrettyString.camelCase(type.getName());
		learn.fact(symURI, NS_MIB+"syntax", NS_MIB+prettyType);
		learn.fact(NS_MIB+prettyType, COMMONS.A, NS_MIB+"StringType");
	}

	public String getSymbolicPath(MibValueSymbol sym) {
		StringBuffer path = new StringBuffer();
		symbolicPath(path,sym);
		return path.toString();
	}

	private void symbolicPath(StringBuffer path, MibValueSymbol sym) {
		if (path.length()==0) path.insert(0,sym.getName());
		else path.insert(0,sym.getName()+":");
		if (sym.getParent()!=null) symbolicPath(path, sym.getParent());
	}

	protected String comments(String comment) {
		if (comment==null) return "";
		comment = comment.trim().replaceAll("\\s+", " ");
		try {
			if (comment.length()>200) return comment.substring(0,200);
			else return comment;
		} catch(NoSuchElementException e) {
			//           log.warn("Summary Failed: "+comment,e);
			return "";
		}

	}
}
