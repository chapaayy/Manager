"use strict";

function bindEvents(){
  bindNodeWorkspace();
  bindNodeListEvents();
  bindLibraryEvents();
  bindSettingsEvents();

  $("login-form").addEventListener("submit",async e=>{
    e.preventDefault();
    const button=e.currentTarget.querySelector("button");
    button.disabled=true;
    $("login-error").textContent="";
    try{
      await signIn(
        $("login-username").value.trim(),
        $("login-password").value
      );
      $("login-password").value="";
    }catch(err){
      $("login-error").textContent=err.message;
    }finally{
      button.disabled=false;
    }
  });

  document.querySelectorAll(".nav-link").forEach(button=>
    button.addEventListener("click",()=>showPage(button.dataset.page))
  );

  $("toggle-sidebar").onclick=()=>{
    const collapsed=$("sidebar").classList.toggle("collapsed");
    $("toggle-sidebar").title=collapsed?"Развернуть меню":"Свернуть меню";
    try{
      localStorage.setItem("xppn-v2-collapsed",collapsed?"1":"0");
    }catch{}
  };

  $("refresh").onclick=()=>refresh()
    .then(()=>message("Данные обновлены"))
    .catch(error=>message(error.message,true));

  $("modal-close").onclick=()=>$("modal").close();
}

document.addEventListener("DOMContentLoaded",start);
