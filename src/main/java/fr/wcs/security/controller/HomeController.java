package fr.wcs.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @GetMapping("/")
    public String welcome(){
        return "Welcome to the SHIELD";
    }

    @GetMapping("/avengers/assemble")
    public String champion(){
        return "Avengers... Assemble";
    }

    @GetMapping("/secret-bases")
    public String director(){
        return "Biarritz, Bordeaux, La Loupe, Lille, Lyon, Nantes, Orléans, Paris, Reims, Strasbourg, Toulouse, Amsterdam, Barcelone, Berlin, Lisbonne, Madrid";
    }
}
