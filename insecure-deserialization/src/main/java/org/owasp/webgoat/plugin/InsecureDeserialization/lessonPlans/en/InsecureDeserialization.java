package org.owasp.webgoat.plugin;

import java.util.*;
import org.apache.ecs.*;
import org.apache.ecs.html.*;
import org.owasp.webgoat.lessons.Category;
import org.owasp.webgoat.lessons.SequentialLessonAdapter;
import org.owasp.webgoat.session.DatabaseUtilities;
import org.owasp.webgoat.session.ECSFactory;
import org.owasp.webgoat.session.WebSession;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ByteArrayInputStream;
import java.util.concurrent.TimeUnit;
import java.io.Serializable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.net.URLDecoder;
import java.util.Base64;

/***************************************************************************************************
 * 
 * 
 * This file is part of WebGoat, an Open Web Application Security Project utility. For details,
 * please see http://www.owasp.org/
 * 
 * Copyright (c) 2002 - 20014 Bruce Mayhew
 * 
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with this program; if
 * not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 * 
 * Getting Source ==============
 * 
 * Source for this application is maintained at https://github.com/WebGoat/WebGoat, a repository for free software
 * projects.
 * 
 * For details, please see http://webgoat.github.io
 * 
 * @author Bruce Mayhew <a href="http://code.google.com/p/webgoat">WebGoat</a>
 * @created October 28, 2003
 */

public class InsecureDeserialization extends SequentialLessonAdapter implements Serializable{

    private final static Logger LOG = LoggerFactory.getLogger(InsecureDeserialization.class);
    // define a constant for the field name
    private static final String INPUT = "input";
    private String token;
        
    protected Element createContent(WebSession s)
    {
        ElementContainer ec = new ElementContainer();
        try
        {
            String b64token, result = "", output = "";
            byte [] data;
            ObjectInputStream ois;
            Object o;
            long before, after;
            int delay;
            boolean failed = false;

            // Create Input
            ec.addElement(new P());
            ec.addElement(new Div().addElement(new StringElement("Try to change this serialized object in order to put a test file here: /tmp/test.")));
            token = s.getParser().getRawParameter(INPUT, "rO0ABXQAVklmIHlvdSBkZXNlcmlhbGl6ZSBtZSBkb3duLCBJIHNoYWxsIGJlY29tZSBtb3JlIHBvd2VyZnVsIHRoYW4geW91IGNhbiBwb3NzaWJseSBpbWFnaW5l");
            Input serializedToken = new Input(Input.TEXT, INPUT, token.toString());
            ec.addElement(serializedToken);

            // Submit Button
            ec.addElement(new P());
            ec.addElement(new Div().addElement(new StringElement("Submit button:")));
            String submittext = "Submit";
            Element b = ECSFactory.makeButton(submittext);
            ec.addElement(b);
            
            // b64token = token.replace('-', '+').replace('_', '/');
            

            byte[] decoded = null;
            String urlDecoded = "";
            try {
                urlDecoded = URLDecoder.decode(token, "UTF-8");
                urlDecoded = urlDecoded
                        .replace(" ", "+")
                        .replace('-', '+')
                        .replace('_', '/')
                        .replace("=", "");
                LOG.info("Payload: " + token);
                decoded = Base64.getDecoder().decode(urlDecoded);

            } catch(Exception e){
                LOG.error("Base64 decoded: " + urlDecoded);
                LOG.error("Base64 decoding exception: " + token, e);
                result = "Base64 error";
            }
            try {

                if (decoded == null || decoded.length == 0){
                    result = "Nothing to deserialize";
                }

                ByteArrayInputStream bis = new ByteArrayInputStream(decoded);
                ObjectInputStream in = new ObjectInputStream(bis);
                LOG.info("Going to deserialize...");

                try {
                    final Object obj = in.readObject();
                    LOG.info("Deserialized");

                    if (obj == null){
                        LOG.info("Deserialized: null");
                    }

                    File tempFile = new File("/tmp/test");
                    boolean fileExists = tempFile.exists();


                    if ( tempFile.exists() ) {
                        result = "Success!";
                        tempFile.delete();
                        return makeSuccess(s);   
                    } else {
                        result = "File is not there yet.";
                    }

                    LOG.info("Obj: " + obj.getClass().getCanonicalName());
                    LOG.info("Deserialized: " + obj);
                    output = "Deserialized Object Is: " + obj; 
                } catch(EOFException e){
                    LOG.error("Deserialization exception", e);
                }
            } catch (Exception e) {
                result = e.toString();
            }

            ec.addElement(new P());
            ec.addElement(new Div().addElement(new StringElement(result)));
            ec.addElement(new P());
            ec.addElement(new Div().addElement(new StringElement(output)));

        }
        catch (Exception e)
        {
            s.setMessage("Error generating " + this.getClass().getName());
            e.printStackTrace();
        }
        return (ec);
    }


    /**
     * Gets the category attribute of the Insecure Deserialization object
     * 
     * @return The category value
     */
    protected Category getDefaultCategory()
    {
        return Category.INSECURE_COMMUNICATION;
    }

    /**
     * Gets the hints attribute of the DatabaseFieldScreen object
     * 
     * @return The hints value
     */
    protected List<String> getHints()
    {
        List<String> hints = new ArrayList<String>();
        hints.add("Insecure Deserialization Hint 1");
        hints.add("Insecure Deserialization Hint 2");
        hints.add("Insecure Deserialization Hint 3");
        
        return hints;
    }

    protected String getInstructions()
    {
        // Instructions will rendered as html and will appear below
        // the area and above the actual lesson area.
        // Instructions should provide the user with the general setup
        // and goal of the lesson.
            
        return("The text that goes at the top of the page");
    }


    private final static Integer DEFAULT_RANKING = new Integer(1);

    protected Integer getDefaultRanking()
    {
        return DEFAULT_RANKING;
    }

    /**
     * Gets the title attribute of the DatabaseFieldScreen object
     * 
     * @return The title value
     */
    public String getTitle()
    {
        return ("Insecure Deserialization");
    }

}