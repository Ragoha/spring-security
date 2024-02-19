package com.cos.security1.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IndexController {

    //localhost:8080/
    //localhost:8080
    @GetMapping({"","/"})
    // 머스테치 기본폴더 src/main/resource/
    // 뷰리졸버 설정 : templates (prefix), .mustache (suffix) (생략가능)
    public String index(){
        return "index"; // src/main/resources/templates/index.mustache
    }
}
