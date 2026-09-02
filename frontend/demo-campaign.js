const liveLoadCampaigns=loadCampaigns;
loadCampaigns=async function(){
  const o=document.getElementById("campaignOutput");
  if(typeof demoMode!=="undefined"&&demoMode){
    o.innerHTML='<div class="threat"><div><b>CAMP-DEMO-001</b><small>Related phishing emails detected across the demo inbox</small></div><span class="badge">CAMPAIGN</span></div><div class="scan-result" style="margin-top:10px">Demo correlation active · multiple look-alike domains and urgent credential lures grouped</div>';
    requestAnimationFrame(bind3DTilt);
    return;
  }
  return liveLoadCampaigns();
};
