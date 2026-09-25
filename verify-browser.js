document.addEventListener("DOMContentLoaded",()=> {
  const $=id=>document.getElementById(id);
  const out=$("verify-results"), cmd=$("cosign-command");
  const publicOut=$("public-verify-results"), publicCmd=$("public-command");
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
    const cls=["VERIFIED","AUTHENTICATED"].includes(state)?"ok":state==="FAILED"?"bad":"neutral";
    return `<div class="browser-check"><div>${esc(label)}</div><strong class="${cls}">${esc(state)}</strong><div>${detail||"—"}</div></div>`;
  }
  function esc(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));}
  function shellQuote(s){return "'"+String(s).replaceAll("'","'\\''")+"'";}
  function shortHash(s){return typeof s==="string" && s.length>18 ? s.slice(0,12)+"…"+s.slice(-8) : (s||"—");}

  async function verifyPublic(){
    publicOut.innerHTML="";
    const reportFile=$("public-report-file").files[0];
    const recordFile=$("public-record-file").files[0];
    try{
      if(!reportFile) throw new Error("Asimov report is required.");
      const record=await readJson(recordFile,"Public verification record");
      if(record.version!=="asimov-public-verification/0.2.0") throw new Error("Unsupported public verification record version.");
      if(!record.report || !record.statement || typeof record.statement.text!=="string") throw new Error("Public verification record is incomplete.");

      const reportDigest=await digestFile(reportFile);
      const statementDigest=await digestText(record.statement.text);
      let statement;
      try{statement=JSON.parse(record.statement.text)}catch(e){throw new Error("Embedded verification statement is invalid JSON.");}

      const subjectName="report/"+record.report.name;
      const reportSubject=(statement.subject||[]).find(x=>x && x.name===subjectName);
      const subjectDigest=reportSubject && reportSubject.digest && reportSubject.digest.sha256;
      const localErrors=[];
      if(statementDigest!==record.statement.sha256) localErrors.push("embedded statement digest mismatch");
      if(reportDigest!==record.report.sha256) localErrors.push("report digest mismatch");
      if(subjectDigest!==reportDigest) localErrors.push("statement does not bind this report digest");
      if(statement._type!=="https://in-toto.io/Statement/v1") localErrors.push("unexpected statement type");
      if(statement.predicateType!=="https://asimov-safety.github.io/asimov/attestation/v0.2") localErrors.push("unexpected predicate type");

      let html=row(
        "Report integrity",
        localErrors.length?"FAILED":"VERIFIED",
        localErrors.length?esc(localErrors.join("; ")):"This exact report matches the SHA-256 digest bound in the issued statement."
      );

      const p=statement.predicate||{};
      const sys=p.system||{};
      if(!localErrors.length){
        html+=`<div class="public-binding">
          <div><span>Report ID</span><strong>${esc(p.reportId||"—")}</strong></div>
          <div><span>System</span><strong>${esc(sys.id||"—")}</strong></div>
          <div><span>Requested profile</span><strong>${esc(p.requestedProfile||"—")}</strong></div>
          <div><span>Reported outcome</span><strong>${esc(p.reportedOutcome||"—")}</strong></div>
          <div><span>Assessment mode</span><strong>${esc(p.assessmentMode||"—")}</strong></div>
          <div><span>Assessment created</span><strong>${esc(p.assessmentCreatedAt||"—")}</strong></div>
          <div><span>Configuration</span><strong title="${esc(sys.configurationSha256||"")}">${esc(shortHash(sys.configurationSha256))}</strong></div>
          <div><span>Scope binding</span><strong title="${esc(p.scopeManifestSha256||"")}">${esc(shortHash(p.scopeManifestSha256))}</strong></div>
        </div>`;
      }

      const sig=record.sigstore;
      const endpoint=document.body.dataset.sigstoreEndpoint||"";
      let provenanceState="UNSIGNED";
      let provenanceDetail="This report matches its public record, but no authenticated signer proof is included.";
      if(sig && typeof sig==="object"){
        const identity=sig.certificate_identity||"";
        const issuer=sig.certificate_oidc_issuer||"";
        if(!identity || !issuer || !sig.bundle){
          provenanceState="FAILED";
          provenanceDetail="The public record contains incomplete Sigstore material.";
        }else if(endpoint){
          const fd=new FormData();
          fd.append("statement",new Blob([record.statement.text],{type:"application/json"}),"asimov-statement.json");
          fd.append("bundle",new Blob([JSON.stringify(sig.bundle)],{type:"application/json"}),"asimov.sigstore.json");
          fd.append("certificate_identity",identity);
          fd.append("certificate_oidc_issuer",issuer);
          try{
            const resp=await fetch(endpoint,{method:"POST",body:fd});
            const data=await resp.json();
            provenanceState=data.verified?"AUTHENTICATED":"FAILED";
            provenanceDetail=data.verified
              ? "Sigstore verified the exact statement for "+identity+" via "+issuer+"."
              : (data.detail||"Sigstore verification failed.");
          }catch(e){
            provenanceState="FAILED";
            provenanceDetail="The Sigstore verifier service could not be reached.";
          }
        }else{
          provenanceState="NOT CHECKED";
          provenanceDetail="Sigstore material is present for "+identity+" via "+issuer+", but this site has no online cryptographic verifier configured. Use the CLI command below.";
          publicCmd.textContent="asimov verify-report "+shellQuote(reportFile.name)+" "+shellQuote(recordFile.name);
        }
      }
      html+=row("Signer provenance",provenanceState,esc(provenanceDetail));

      const overall=localErrors.length?"FAILED":provenanceState==="AUTHENTICATED"?"AUTHENTICATED":"LOCAL MATCH";
      html=row("Public verification",overall,
        overall==="AUTHENTICATED"
          ?"The report is intact and its issued statement has authenticated signer provenance."
          : overall==="LOCAL MATCH"
            ?"The report matches the published verification record. Signer provenance is not cryptographically authenticated here."
            :"The supplied report or verification record failed integrity checks."
      )+html;

      html+=row("Semantic assurance","SEPARATE REVIEW","A valid signature proves provenance and binding; it does not decide whether the assessment evidence or conclusion is substantively correct.");
      publicOut.innerHTML=html;
    }catch(e){
      publicOut.innerHTML=row("Public verification","FAILED",esc(e.message||e));
    }
  }

  async function verifyFull(){
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
        html+=row("Evidence files",errors.length?"FAILED":"VERIFIED",errors.length?esc(errors.slice(0,8).join("; ")):"Selected directory matches the manifest.");
      } else {
        html+=row("Evidence files","NOT CHECKED","Select the evidence directory to verify every bound file locally.");
      }

      const expectedSubjects=new Map();
      expectedSubjects.set("asimov-assessment",await digestFile(assessmentFile));
      expectedSubjects.set("asimov-evidence-manifest",await digestFile(manifestFile));
      if(reportFile) expectedSubjects.set("report/"+reportFile.name,await digestFile(reportFile));
      const actualSubjects=new Map((statement.subject||[]).map(x=>[x.name,x.digest&&x.digest.sha256]));
      const subjectErrors=[];
      for(const [name,digest] of expectedSubjects){
        if(!actualSubjects.has(name)) subjectErrors.push("missing subject "+name);
        else if(actualSubjects.get(name)!==digest) subjectErrors.push("digest mismatch "+name);
      }
      for(const name of actualSubjects.keys()) if(!expectedSubjects.has(name)) subjectErrors.push("unexpected subject "+name);
      const subjectOk=subjectErrors.length===0;
      html+=row("Artifact binding",subjectOk?"VERIFIED":"FAILED",subjectOk?"Assessment, manifest"+(reportFile?", and report":"")+" hashes match the statement.":esc(subjectErrors.join("; ")));

      const p=statement.predicate||{};
      const predicateErrors=[];
      const check=(ok,label)=>{if(!ok) predicateErrors.push(label)};
      check(statement._type==="https://in-toto.io/Statement/v1","statement type");
      check(statement.predicateType==="https://asimov-safety.github.io/asimov/attestation/v0.2","predicate type");
      check(p.specVersion===assessment.spec_version,"spec version");
      check(p.reportId===assessment.report_id,"report ID");
      check(p.system && p.system.id===assessment.system.id,"system ID");
      check(p.system && p.system.configurationSha256===assessment.system.configuration_sha256,"configuration SHA-256");
      check(p.scopeManifestSha256===assessment.scope_manifest_sha256,"scope manifest SHA-256");
      check(p.requestedProfile===assessment.requested_profile,"requested profile");
      check(p.assessmentMode===(assessment.assessment&&assessment.assessment.mode),"assessment mode");
      check(p.evidenceManifestSha256===manifest.manifest_sha256,"evidence manifest SHA-256");
      const predicateOk=predicateErrors.length===0;
      html+=row("Scope & configuration",predicateOk?"VERIFIED":"FAILED",predicateOk?"Statement predicate matches the assessment scope and configuration.":esc("Mismatched: "+predicateErrors.join(", ")));

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

  $("verify-public").addEventListener("click",verifyPublic);
  $("verify-local").addEventListener("click",verifyFull);
  $("copy-cosign").addEventListener("click",async()=>{if(cmd.textContent) await navigator.clipboard.writeText(cmd.textContent)});
});