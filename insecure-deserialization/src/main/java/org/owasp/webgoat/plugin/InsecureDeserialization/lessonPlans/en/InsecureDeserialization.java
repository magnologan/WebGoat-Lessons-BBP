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

public class InsecureDeserialization extends SequentialLessonAdapter {

    // define a constant for the field name
    private static final String INPUT = "input";
    private String token;
        
    protected Element createContent(WebSession s)
    {
        ElementContainer ec = new ElementContainer();
        try
        {
            String b64token, result;
            byte [] data;
            ObjectInputStream ois;
            Object o;
            long before, after;
            int delay;
            boolean failed = false;

            // Create Input
            ec.addElement(new P());
            ec.addElement(new Div().addElement(new StringElement("Try to change this serialized object in order to delay the page response for exactly 5 seconds.")));
            token = s.getParser().getRawParameter(INPUT, "rO0ABXQAVklmIHlvdSBkZXNlcmlhbGl6ZSBtZSBkb3duLCBJIHNoYWxsIGJlY29tZSBtb3JlIHBvd2VyZnVsIHRoYW4geW91IGNhbiBwb3NzaWJseSBpbWFnaW5l");
            Input serializedToken = new Input(Input.TEXT, INPUT, token.toString());
            ec.addElement(serializedToken);

            // Submit Button
            ec.addElement(new P());
            ec.addElement(new Div().addElement(new StringElement("Submit button:")));
            String submittext = "Submit";
            Element b = ECSFactory.makeButton(submittext);
            ec.addElement(b);
            
            b64token = token.replace('-', '+').replace('_', '/');

            try {
                data = Base64.getDecoder().decode(b64token);

                String test = new String(data);
                System.out.println(test);
                ois = new ObjectInputStream( new ByteArrayInputStream(data) );    

                before = System.currentTimeMillis();

                try {
                    o = ois.readObject();
                } catch (Exception e) {
                    o = null;
                }
                after = System.currentTimeMillis();
                ois.close();

                delay = (int)(after - before);
                if ( delay > 7000 ) {
                    result = "Too long... Failed.";
                } else if ( delay < 3000 ) {
                    result = "Too short... Failed.";
                } else {
                    result = "Congrats!";
                    //return makeSuccess(s);   
                }

            } catch (Exception e) {
                result = "Not Base64!";
            }

            ec.addElement(new P());
            ec.addElement(new Div().addElement(new StringElement(result)));

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