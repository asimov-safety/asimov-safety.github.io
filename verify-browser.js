document.addEventListener("DOMContentLoaded",()=> {
  const $=id=>document.getElementById(id);
  const out=$("verify-results"), cmd=$("cosign-command");
  const enc=new TextEncoder();

  function sorted(v){
    if(Array.isArray(v)) return v.map(sorted);
    if(v && typeof v==="object"){
      const o={}; Object.keys(v).sort().forEach(k=>o[k]=sorted(v[k])); return o;
    }
    return v;
  }
  function canonical(v){ return JSON.stringify(sorted(v)); }
  async function hexDigestBytes(bytes){
    const hash=await crypto.subtle.digest("SHA-256",bytes);
    return [...new Uint8Array(hash)].map(x=>x.toString(16).padStart(2,"0")).join("");
  }
  async function digestFile(file){ return hexDigestBytes(await file.arrayBuffer()); }
  async function digestText(text){ return hexDigestBytes(enc.encode(text)); }
  async function readJson(file,label){
    if(!file) throw new Error(label+" is required.");
    try{return JSON.parse(await file.text())}catch(e){throw new Error(label+" is not valid JSON.")}
  }
  function row(label,state,detail){
    const cls=state==="VERIFIED"?"ok":state==="FAILED"?"bad":"neutral";
    return `<div class="browser-check"><div>${label}</div><strong class="${cls}">${state}</strong><div>${detail||"—"}</div></div>`;
  }
  function esc(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));}
  function shellQuote(s){return "'"+String(s).replaceAll("'","'\\''")+"'";}

  async function verify(){
    out.innerHTML="";
    cmd.textContent="";
    const assessmentFile=$("assessment-file").files[0];
    const manifestFile=$("manifest-file").files[0];
    const statementFile=$("statement-file").files[0];
    const reportFile=$("report-file").files[0];
    const bundleFile=$("bundle-file").files[0];
    const identity=$("cert-identity").value.trim();
    const issuer=$("oidc-issuer").value.trim();

    try{
      const [assessment,manifest,statement]=await Promise.all([
        readJson(assessmentFile,"Assessment"),
        readJson(manifestFile,"Evidence manifest"),
        readJson(statementFile,"Verification statement")
      ]);

      const manifestContent={version:manifest.version,algorithm:manifest.algorithm,files:manifest.files};
      const manifestExpected=await digestText(canonical(manifestContent));
      const manifestOk=manifestExpected===manifest.manifest_sha256;
      let html=row("Manifest self-digest",manifestOk?"VERIFIED":"FAILED",manifestOk?"Deterministic manifest digest matches.":"Manifest digest mismatch.");

      const dirFiles=[...$("evidence-dir").files];
      if(dirFiles.length){
        const selected=new Map();
        for(const file of dirFiles){
          let p=file.webkitRelativePath||file.name;
          if(p.includes("/")) p=p.split("/").slice(1).join("/");
          selected.set(p,file);
        }
        const errors=[];
        const bound=new Set();
        for(const item of (manifest.files||[])){
          bound.add(item.path);
          const file=selected.get(item.path);
          if(!file){errors.push("missing "+item.path);continue}
          if(file.size!==item.size) errors.push("size "+item.path);
          if(await digestFile(file)!==item.sha256) errors.push("digest "+item.path);
        }
        for(const p of selected.keys()) if(!bound.has(p)) errors.push("unbound "+p);
        html+=row("Evidence files",errors.length?"FAILED":"VERIFIED",errors.length?errors.slice(0,8).join("; "):"Selected directory matches the manifest.");
      } else {
        html+=row("Evidence files","NOT CHECKED","Select the evidence directory to verify every bound file locally.");
      }

      const expectedSubjects=new Map();
      expectedSubjects.set("asimov-assessment",await digestFile(assessmentFile));
      expectedSubjects.set("asimov-evidence-manifest",await digestFile(manifestFile));
      if(reportFile) expectedSubjects.set("report/"+reportFile.name,await digestFile(reportFile));
      const actualSubjects=new Map((statement.subject||[]).map(x=>[x.name,x.digest&&x.digest.sha256]));
      let subjectOk=expectedSubjects.size===actualSubjects.size;
      if(subjectOk) for(const [k,v] of expectedSubjects) if(actualSubjects.get(k)!==v) subjectOk=false;
      html+=row("Artifact binding",subjectOk?"VERIFIED":"FAILED",subjectOk?"Assessment, manifest"+(reportFile?", and report":"")+" hashes match the signed-subject statement.":"Statement subject digests do not match the selected artifacts.");

      const p=statement.predicate||{};
      const predicateOk=
        statement._type==="https://in-toto.io/Statement/v1" &&
        statement.predicateType==="https://asimov-safety.github.io/asimov/attestation/v0.2" &&
        p.specVersion===assessment.spec_version &&
        p.reportId===assessment.report_id &&
        p.system && p.system.id===assessment.system.id &&
        p.system.configurationSha256===assessment.system.configuration_sha256 &&
        p.scopeManifestSha256===assessment.scope_manifest_sha256 &&
        p.requestedProfile===assessment.requested_profile &&
        p.assessmentMode===assessment.assessment.mode &&
        p.evidenceManifestSha256===manifest.manifest_sha256;
      html+=row("Scope & configuration",predicateOk?"VERIFIED":"FAILED",predicateOk?"Statement predicate matches the assessment scope and configuration.":"Statement predicate does not match the assessment.");

      const endpoint=document.body.dataset.sigstoreEndpoint||"";
      if(bundleFile && identity && issuer && endpoint){
        const fd=new FormData();
        fd.append("statement",statementFile);
        fd.append("bundle",bundleFile);
        fd.append("certificate_identity",identity);
        fd.append("certificate_oidc_issuer",issuer);
        try{
          const resp=await fetch(endpoint,{method:"POST",body:fd});
          const data=await resp.json();
          html+=row("Sigstore identity & transparency",data.verified?"VERIFIED":"FAILED",esc(data.detail||"Sigstore verification completed."));
        }catch(e){
          html+=row("Sigstore identity & transparency","FAILED","Verifier service could not be reached.");
        }
      }else if(bundleFile){
        html+=row("Sigstore identity & transparency","CLI VERIFY",identity&&issuer?"Bundle supplied. Use the generated Cosign command below.":"Enter the expected signer identity and OIDC issuer.");
      }else{
        html+=row("Sigstore identity & transparency","NOT CHECKED","Supply a Sigstore bundle to verify signer identity and transparency proof.");
      }

      html+=row("Semantic assurance","REVIEW REQUIRED","Cryptography verifies provenance and binding; an assessor still determines whether the evidence satisfies each Constant.");
      out.innerHTML=html;

      if(bundleFile && identity && issuer){
        cmd.textContent="cosign verify-blob "+shellQuote(statementFile.name)+" --bundle "+shellQuote(bundleFile.name)+" --certificate-identity="+shellQuote(identity)+" --certificate-oidc-issuer="+shellQuote(issuer);
      }
    }catch(e){
      out.innerHTML=row("Verification","FAILED",esc(e.message||e));
    }
  }

  $("verify-local").addEventListener("click",verify);
  $("copy-cosign").addEventListener("click",async()=>{if(cmd.textContent) await navigator.clipboard.writeText(cmd.textContent)});
});