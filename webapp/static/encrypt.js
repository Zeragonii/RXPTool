"use strict";
(() => {
  const get = id => document.getElementById(id);
  const ids = ['encryptForm','encryptId','rememberEncryptId','encryptFile',
    'encryptDrop','encryptFileTitle','encryptFileDescription','clearEncryptFile',
    'encryptError','encryptSubmit','encryptSubmitLabel','encryptEmpty',
    'encryptLoading','encryptResult','encryptInputSize','encryptOutputSize',
    'encryptGuideCount','downloadEncrypted','toggleEncryptId',
    'encryptSuccessTitle','encryptSuccessSubtitle','encryptResultHint'];
  const missing = ids.filter(id => !get(id));
  if (missing.length) {
    const error = document.createElement('p'); error.className = 'frontend-mismatch';
    error.textContent = 'RXPTool assets are out of sync. Hard-refresh (Ctrl+Shift+R). Missing: ' + missing.join(', ');
    document.body.prepend(error); return;
  }
  const id = get('encryptId'), upload = get('encryptFile');
  const drop = get('encryptDrop'), error = get('encryptError');
  const submit = get('encryptSubmit'), remember = get('rememberEncryptId');
  let selected = null, result = null, epoch = 0;
  const show = (name, state) => { get(name).hidden = !state; };
  const size = n => n >= 1048576 ? (n/1048576).toFixed(1)+' MiB' : Math.max(1,Math.round(n/1024))+' KiB';
  const fail = message => { error.textContent = message; error.hidden = false; };
  const clearError = () => { error.textContent=''; error.hidden=true; };
  const storageKey='rxp-decode-account-id';
  try { const old=localStorage.getItem(storageKey); if (old) { id.value=old; remember.checked=true; } } catch (_) {}
  const saveId=()=>{try {if(remember.checked) localStorage.setItem(storageKey,id.value.trim()); else localStorage.removeItem(storageKey);} catch (_) {}};
  remember.addEventListener('change',saveId);
  id.addEventListener('input',()=>{if(remember.checked)saveId(); reset();});
  get('toggleEncryptId').addEventListener('click',()=>{
    id.type=id.type==='password'?'text':'password';
    get('toggleEncryptId').setAttribute('aria-label',id.type==='text'?'Hide account ID':'Show account ID');
  });
  function reset() {epoch++;result=null;show('encryptEmpty',true);show('encryptLoading',false);show('encryptResult',false);}
  async function chooseFile(file) {
    if(!file)return;
    if(file.size>16*1024*1024 || file.size<1){fail('Editable TXT must be between 1 byte and 16 MiB.');return;}
    if(!file.name.toLowerCase().endsWith('.txt')){fail('Only editable .txt files are supported.');return;}
    selected=file;reset();clearError();
    get('encryptFileTitle').textContent=file.name;
    get('encryptFileDescription').textContent=size(file.size)+' · Ready to encrypt';
    show('clearEncryptFile',true);
  }
  drop.addEventListener('click',()=>upload.click());
  drop.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();upload.click();}});
  upload.addEventListener('change',()=>chooseFile(upload.files?.[0]));
  ['dragenter','dragover'].forEach(event=>drop.addEventListener(event,e=>{e.preventDefault();drop.classList.add('dragging');}));
  ['dragleave','drop'].forEach(event=>drop.addEventListener(event,e=>{e.preventDefault();drop.classList.remove('dragging');}));
  drop.addEventListener('drop',e=>chooseFile(e.dataTransfer?.files?.[0]));
  get('clearEncryptFile').addEventListener('click',()=>{
    selected=null;upload.value='';reset();clearError();
    get('encryptFileTitle').textContent='Drop editable_guides.txt here';
    get('encryptFileDescription').textContent='or browse your files to select the editable TXT';
    show('clearEncryptFile',false);
  });
  const toBase64=bytes=>{
    const parts=[];for(let i=0;i<bytes.length;i+=16384){parts.push(String.fromCharCode(...bytes.subarray(i,i+16384)));}
    return btoa(parts.join(''));
  };
  get('encryptForm').addEventListener('submit',async e=>{
    e.preventDefault(); if(submit.disabled)return;
    const account=id.value.trim();
    if(!account){fail('Enter the Battle.net ID for output encryption.');id.focus();return;}
    if(!selected){fail('Select editable_guides.txt first.');return;}
    const probe=(await selected.slice(0,32).text()).replace(/^\uFEFF/,'');
    if(!/^#!RXPTOOL\/1\r?\n/.test(probe)){fail('This is not a self-contained RXPTool Editable guide TXT.');return;}
    saveId();clearError();reset();
    const request=epoch;submit.disabled=true;get('encryptSubmitLabel').textContent='Encrypting…';
    show('encryptEmpty',false);show('encryptLoading',true);
    try {
      const encoded=toBase64(new Uint8Array(await selected.arrayBuffer()));
      const response=await fetch('/api/encrypt',{method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({battle_id:account,content_base64:encoded}),cache:'no-store'});
      if(!response.ok){let message=`Encryption failed (HTTP ${response.status})`;
        try{message=(await response.json()).error||message;}catch(_){} throw new Error(message);}
      const blob=await response.blob();if(request!==epoch)return;
      result=blob;
      get('encryptSuccessTitle').textContent='Import rebuilt and verified';
      get('encryptSuccessSubtitle').textContent='Fresh encryption · full import framing';
      get('encryptResultHint').textContent='RXPTool independently decrypted the result and verified the reconstructed plaintext and guide count.';
      get('encryptInputSize').textContent=size(selected.size);
      get('encryptOutputSize').textContent=size(blob.size);
      get('encryptGuideCount').textContent=response.headers.get('X-Guide-Count')||'—';
      show('encryptLoading',false);show('encryptResult',true);
    }catch(exc){if(request===epoch){reset();fail(exc?.message||'Unable to encrypt guides.');}}
    finally{submit.disabled=false;get('encryptSubmitLabel').textContent='Encrypt guides';}
  });
  get('downloadEncrypted').addEventListener('click',()=>{
    if(!result)return;
    const url=URL.createObjectURL(result),a=document.createElement('a');
    a.href=url;a.download='rebuilt_import.txt';a.hidden=true;
    document.body.append(a);a.click();a.remove();
    setTimeout(()=>URL.revokeObjectURL(url),3000);
  });
})();
