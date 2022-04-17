package com.uniovi.sdi2122317spring.pageobjects;

import com.uniovi.sdi2122317spring.util.SeleniumUtils;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

import java.sql.Driver;
import java.util.List;

public class PO_PrivateView extends PO_NavView {
    static public void fillFormAddMark(WebDriver driver, int userOrder, String descriptionp, String scorep)
    {
        //Esperamos 5 segundo a que carge el DOM porque en algunos equipos falla
        SeleniumUtils.waitSeconds(driver, 5);
        //Seleccionamos el alumnos userOrder
        new Select(driver.findElement(By.id("user"))).selectByIndex(userOrder);
        //Rellenemos el campo de descripción
        WebElement description = driver.findElement(By.name("description"));
        description.clear();
        description.sendKeys(descriptionp);
        WebElement score = driver.findElement(By.name("score"));
        score.click();
        score.clear();
        score.sendKeys(scorep);
        By boton = By.className("btn");
        driver.findElement(boton).click();
    }
    static  public List<WebElement> getRows(WebDriver driver, String criteria, String text){
        List<WebElement> markList = SeleniumUtils.waitLoadElementsBy(driver, criteria, text,
                PO_View.getTimeout());
        return markList;

    }
    static public void countMarks(WebDriver driver, String path){
        By enlace = By.xpath("//td[contains(text(), 'Nota A2')]/following-sibling::*[2]");
        driver.findElement(enlace).click();
    }
    static public void directLogin(WebDriver driver,String dni,String password ){
        //Vamos al formulario de logueo.
        PO_HomeView.clickOption(driver, "login", "class", "btn btn-primary");
        //Rellenamos el formulario
        PO_LoginView.fillLoginForm(driver, dni, password);
    }
    static public  void clickElementX(WebDriver driver,String type,String component,int element){
        List<WebElement> elements = PO_View.checkElementBy(driver, type, component);
        elements.get(element).click();
    }

    static  public void waitNoElement(WebDriver driver ,String element){
        SeleniumUtils.waitTextIsNotPresentOnPage(driver, element,PO_View.getTimeout());
    }
}
