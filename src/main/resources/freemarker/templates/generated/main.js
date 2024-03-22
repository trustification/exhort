!function(){"use strict";var e={31958:function(e,n,r){var i=r(68963),t=r(63609),a=(r(13218),r(19559)),s=r(39714),o=r(34187),c=r(15671),l=r(43144),d="maven",u="https://pkg.go.dev/",h="https://www.npmjs.com/package/",g="https://pypi.org/project/",v="__ISSUE_ID__",p="pkg:",x=["oss-index"],j="https://maven.repository.redhat.com/ga/",f=function(e){return"oss-index"===e?"https://ossindex.sonatype.org/user/register":""},m=function(e,n){var r=D.fromString(e),i=function(e){var n="";return e.namespace&&(n=e.type===d?"".concat(e.namespace,":"):"".concat(e.namespace,"/")),n+"".concat(e.name)}(r);return n?i+"@".concat(r.version):i},y=function(e){var n=D.fromString(e),r=j;if(n.namespace){var i,t=null===(i=n.namespace)||void 0===i?void 0:i.replace(/\./g,"/");return"".concat(j).concat(t,"/").concat(n.name,"/").concat(n.version)}return r},I=function(e){var n=D.fromString(e);switch(n.type){case d:var r=n.version;if(null!==r&&void 0!==r&&r.includes("redhat")){var i,t=null===(i=n.namespace)||void 0===i?void 0:i.replace(/\./g,"/");return"".concat(j).concat(t,"/").concat(n.name,"/").concat(n.version)}return"".concat("https://central.sonatype.com/artifact/").concat(n.namespace,"/").concat(n.name,"/").concat(n.version);case"golang":var a=n.version;return null!==a&&void 0!==a&&a.match(/v\d\.\d.\d-\d{14}-\w{12}/)?"".concat(u).concat(n.namespace,"/").concat(n.name):"".concat(u).concat(n.namespace,"/").concat(n.name,"@").concat(n.version);case"npm":return n.namespace?"".concat(h).concat(n.namespace,"/").concat(n.name,"/v/").concat(n.version):"".concat(h).concat(n.name,"/v/").concat(n.version);case"pypi":return n.namespace?"".concat(g).concat(n.namespace,"/").concat(n.name,"/").concat(n.version):"".concat(g).concat(n.name,"/").concat(n.version);default:return n.toString()}},b=function(e){var n=D.fromString(e).version;return n||""},C=function(e,n,r){switch(e){case"snyk":return r.snykIssueTemplate.replace(v,n);case"oss-index":return r.ossIssueTemplate.replace(v,n);case"osv-nvd":return r.nvdIssueTemplate.replace(v,n)}},M=function(e){return e.toLowerCase().replace(/./,(function(e){return e.toUpperCase()}))},T=function(e){var n=A(e),r="";if(n.repository_url){var i=n.repository_url.indexOf("/");r+=-1!==i?n.repository_url.substring(i+1):""}else r+="".concat(n.short_name);return n.tag&&(r+=":".concat(n.tag)),r},A=function(e){var n=e.split("?"),r=n[0],i=n[1],t=new URLSearchParams(i),a=t.get("repository_url")||"",s=t.get("tag")||"",o=t.get("arch")||"",c=r.split("@");return{repository_url:a,tag:s,short_name:c[0].substring(c[0].indexOf("/")+1),version:r.substring(r.lastIndexOf("@")).replace("%3A",":"),arch:o}},S=function(e,n,r){var i=N(n);for(var t in i){var a=i[t].report.dependencies;if(a){var s=Object.values(a).find((function(n){var r=n.ref,i=decodeURIComponent(r);return D.fromString(i).toString()===D.fromString(e).toString()}));if(s&&s.recommendation){var o=decodeURIComponent(s.recommendation),c=w(o,r);if(void 0!==c)return c}}}return"https://catalog.redhat.com/software/containers/search"},w=function(e,n){var r=JSON.parse(n).find((function(n){return D.fromString(n.purl).toString()===D.fromString(e).toString()}));return null===r||void 0===r?void 0:r.catalogUrl},D=function(){function e(n,r,i,t){(0,c.Z)(this,e),this.type=void 0,this.namespace=void 0,this.name=void 0,this.version=void 0,this.type=n,this.namespace=r,this.name=i,this.version=t}return(0,l.Z)(e,[{key:"toString",value:function(){var e=this.name;return this.version&&(e+="@".concat(this.version)),this.namespace?"".concat(p).concat(this.type,"/").concat(this.namespace,"/").concat(e):"".concat(p).concat(this.type,"/").concat(e)}}],[{key:"fromString",value:function(n){var r=n.replace(p,""),i=r.indexOf("?");-1!==i&&(r=r.substring(0,i));var t,a,s=r.substring(0,r.indexOf("/")),o=r.split("/");o.length>2&&(t=o.slice(1,o.length-1).join("/")),-1!==r.indexOf("@")&&(a=r.substring(r.indexOf("@")+1));var c=o[o.length-1];return a&&(c=c.substring(0,c.indexOf("@"))),new e(s,t,c,a)}}]),e}();function N(e){var n=[];return Object.keys(e.providers).forEach((function(r){var i=e.providers[r].sources;void 0!==i&&Object.keys(i).length>0?Object.keys(i).forEach((function(e){n.push({provider:r,source:e,report:i[e]})})):"trusted-content"!==r&&n.push({provider:r,source:r,report:{}})})),n.sort((function(e,n){return 0===Object.keys(e.report).length&&0===Object.keys(n.report).length?""===f(e.provider)?""===f(n.provider)?0:-1:1:Object.keys(n.report).length-Object.keys(e.report).length}))}function P(e){return void 0===e?"unknown":e.provider!==e.source?"$item.provider/$item.source":e.provider}function k(e){var n;return!(!e.remediation||!(e.remediation.fixedIn||null!==(n=e.remediation)&&void 0!==n&&n.trustedContent))}function O(e){var n=[];return e.map((function(e){return{dependencyRef:e.ref,vulnerabilities:e.issues||[]}})).forEach((function(e){var r;null===(r=e.vulnerabilities)||void 0===r||r.forEach((function(r){r.cves&&r.cves.length>0?r.cves.forEach((function(i){n.push({id:i,dependencyRef:e.dependencyRef,vulnerability:r})})):n.push({id:r.id,dependencyRef:e.dependencyRef,vulnerability:r})}))})),n.sort((function(e,n){return n.vulnerability.cvssScore-e.vulnerability.cvssScore}))}var Z=r(43442),L=r(73324),z=r(96363),E=r(78437),B=r(26798),R=r(62996),F=r(73020),_=r(34223),H=r(11858),G=r(90493),U=r(47065),V=r(17941),Y=r(82355),J=r(38485),W=r(29090),Q=r(2570),K=r(22124),q=r(75859),X=["#800000","#FF0000","#FFA500","#5BA352"],$=function(e){var n,r,i,t,a,s=e.summary,o=null!==(n=null===s||void 0===s?void 0:s.critical)&&void 0!==n?n:0,c=null!==(r=null===s||void 0===s?void 0:s.high)&&void 0!==r?r:0,l=null!==(i=null===s||void 0===s?void 0:s.medium)&&void 0!==i?i:0,d=null!==(t=null===s||void 0===s?void 0:s.low)&&void 0!==t?t:0,u=null!==(a=null===s||void 0===s?void 0:s.total)&&void 0!==a?a:0,h=o+c+l+d>0,g=h?X:["#D5F5E3"],v=[{name:"Critical: ".concat(o),symbol:{type:"square",fill:X[0]}},{name:"High: ".concat(c),symbol:{type:"square",fill:X[1]}},{name:"Medium: ".concat(l),symbol:{type:"square",fill:X[2]}},{name:"Low: ".concat(d),symbol:{type:"square",fill:X[3]}}];return(0,q.jsx)("div",{children:(0,q.jsx)(_.e,{style:{paddingBottom:"inherit",padding:"0"},children:(0,q.jsx)(Q.b,{children:(0,q.jsx)("div",{style:{height:"230px",width:"350px"},children:(0,q.jsx)(K.H,{constrainToVisibleArea:!0,data:h?[{x:"Critical",y:o},{x:"High",y:c},{x:"Medium",y:l},{x:"Low",y:d}]:[{x:"Empty",y:1e-10}],labels:function(e){var n=e.datum;return"".concat(n.x,": ").concat(n.y)},legendData:v,legendOrientation:"vertical",legendPosition:"right",padding:{left:20,right:140},subTitle:"Unique vulnerabilities",title:"".concat(u),width:350,colorScale:g})})})})})},ee=r(66155),ne="data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHN2ZyB3aWR0aD0iMTJweCIgaGVpZ2h0PSIxM3B4IiB2aWV3Qm94PSIwIDAgMTIgMTMiIGlkPSJTZWN1cml0eUNoZWNrSWNvbiIgdmVyc2lvbj0iMS4xIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIj4KICAgIDx0aXRsZT5Db21iaW5lZCBTaGFwZTwvdGl0bGU+CiAgICA8ZyBpZD0iTXVsdGktdmVuZG9yIiBzdHJva2U9Im5vbmUiIHN0cm9rZS13aWR0aD0iMSIgZmlsbD0ibm9uZSIgZmlsbC1ydWxlPSJldmVub2RkIj4KICAgICAgICA8ZyBpZD0iT3ZlcnZpZXctQ29weSIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoLTEyMDcsIC05OTMpIiBmaWxsPSIjM0U4NjM1Ij4KICAgICAgICAgICAgPGcgaWQ9IkRldGFpbHMtb2YtZGVwZW5kZW5jeS1jb20uZ2l0aHViIiB0cmFuc2Zvcm09InRyYW5zbGF0ZSg0MjcsIDgxOSkiPgogICAgICAgICAgICAgICAgPGcgaWQ9IkRlcGVuZGVuY3ktMSIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoMCwgMTQ0KSI+CiAgICAgICAgICAgICAgICAgICAgPGcgaWQ9Ikdyb3VwLTkiIHRyYW5zZm9ybT0idHJhbnNsYXRlKDc4MC4xNzI4LCAyNCkiPgogICAgICAgICAgICAgICAgICAgICAgICA8ZyBpZD0iR3JvdXAtNCIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoMCwgMy4yKSI+CiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZyBpZD0iSWNvbnMvMi4tU2l6ZS1zbS9BY3Rpb25zL2NoZWNrIiB0cmFuc2Zvcm09InRyYW5zbGF0ZSgwLCAyLjgpIj4KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8cGF0aCBkPSJNMTAuNTU2NTc4OSwwIEMxMC43OTA2MjQ5LDAgMTAuOTc5MzMyMiwwLjE4MTU0Mjk2OSAxMC45NzkzMzIyLDAuNDA2MjUgTDEwLjk3OTMzMjIsNS43NDA4MjAzMSBDMTAuOTc5MzMyMiw5Ljc1IDYuMjQwODE5MDcsMTMgNS40OTU3OTI5NiwxMyBDNC43NTA3NjY4NCwxMyAwLDkuNzUgMCw1LjczOTU1MDc4IEwwLDAuNDA2MjUgQzAsMC4xODE1NDI5NjkgMC4xODg3MDcyNzIsMCAwLjQyMjc1MzMwNCwwIFogTTguNTQyNzc4ODMsMy4xMTc4MjY2NyBMNC43OTEyOTYxLDYuODkwODczNTMgTDMuMDM5ODEzMzgsNS4xMjkzMjQ0IEMyLjg4MzYwOSw0Ljk3MjIwNjgzIDIuNjMwMzI4MTIsNC45NzIyMDY4MyAyLjQ3NDEyMzc1LDUuMTI5MzI0NCBMMS45MDg0NDkzOCw1LjY5ODI2NTU2IEMxLjc1MjI0NTAxLDUuODU1MzgzMTIgMS43NTIyNDUwMSw2LjExMDEwNDQ5IDEuOTA4NDQ5MzgsNi4yNjcyMDY3MSBMNC41MDg0NTc5Nyw4Ljg4MjE1OTkxIEM0LjY2NDY0NzA4LDkuMDM5Mjc3NDcgNC45MTc5MTI3LDkuMDM5Mjc3NDcgNS4wNzQxMzIzMyw4Ljg4MjE3NTI1IEw5LjY3NDE0MjgyLDQuMjU1NzA4OTggQzkuODMwMzQ3Miw0LjA5ODU5MTQxIDkuODMwMzQ3MiwzLjg0Mzg3MDA0IDkuNjc0MTQyODIsMy42ODY3Njc4MiBMOS4xMDg0Njg0NiwzLjExNzgyNjY3IEM4Ljk1MjI2NDA4LDIuOTYwNzI0NDQgOC42OTg5ODMyLDIuOTYwNzI0NDQgOC41NDI3Nzg4MywzLjExNzgyNjY3IFoiIGlkPSJDb21iaW5lZC1TaGFwZSI+PC9wYXRoPgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICAgICAgICAgICAgICA8L2c+CiAgICAgICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICA8L2c+CiAgICAgICAgPC9nPgogICAgPC9nPgo8L3N2Zz4=",re=function(e){var n=e.report,r=e.isReportMap,i=e.purl,t=jn();return(0,q.jsxs)(s.r,{hasGutter:!0,children:[(0,q.jsxs)(Z.D,{headingLevel:"h3",size:Z.H["2xl"],style:{paddingLeft:"15px"},children:[(0,q.jsx)(L.J,{isInline:!0,status:"info",children:(0,q.jsx)(W.ZP,{style:{fill:"#f0ab00"}})}),"\xa0Red Hat Overview of security Issues"]}),(0,q.jsx)(z.i,{}),(0,q.jsx)(o.P,{children:(0,q.jsxs)(E.Z,{isFlat:!0,isFullHeight:!0,children:[(0,q.jsx)(B.O,{children:(0,q.jsx)(R.l,{children:(0,q.jsx)(F.M,{style:{fontSize:"large"},children:r?(0,q.jsxs)(q.Fragment,{children:[i?T(i):"No Image name"," - Vendor Issues"]}):(0,q.jsx)(q.Fragment,{children:"Vendor Issues"})})})}),(0,q.jsxs)(_.e,{children:[(0,q.jsx)(H.g,{children:(0,q.jsx)(G.b,{children:(0,q.jsx)(F.M,{children:"Below is a list of dependencies affected with CVE."})})}),(0,q.jsx)(U.o,{isAutoFit:!0,style:{paddingTop:"10px"},children:N(n).map((function(e,n){return(0,q.jsxs)(H.g,{style:{display:"flex",flexDirection:"column",alignItems:"center"},children:[(0,q.jsx)(q.Fragment,{children:(0,q.jsx)(F.M,{style:{fontSize:"large"},children:P(e)})}),(0,q.jsx)(G.b,{children:(0,q.jsx)($,{summary:e.report.summary})})]},n)}))})]}),(0,q.jsx)(z.i,{})]})}),(0,q.jsxs)(o.P,{md:6,children:[(0,q.jsx)(E.Z,{isFlat:!0,children:(0,q.jsxs)(H.g,{children:[(0,q.jsx)(R.l,{component:"h4",children:(0,q.jsxs)(F.M,{style:{fontSize:"large"},children:[(0,q.jsx)(L.J,{isInline:!0,status:"info",children:(0,q.jsx)(ee.ZP,{style:{fill:"#cc0000"}})}),"\xa0 Red Hat Remediations"]})}),(0,q.jsx)(_.e,{children:(0,q.jsx)(G.b,{children:r?(0,q.jsxs)(V.aV,{isPlain:!0,children:[(0,q.jsx)(Y.H,{children:"Switch to UBI 9 for enhanced security and enterprise-grade stability in your containerized applications, backed by Red Hat's support and compatibility assurance."}),(0,q.jsx)(Y.H,{children:(0,q.jsx)("a",{href:i?S(i,n,t.imageMapping):"###",target:"_blank",rel:"noreferrer",children:(0,q.jsx)(J.zx,{variant:"primary",size:"sm",children:"Take me there"})})})]}):(0,q.jsx)(V.aV,{isPlain:!0,children:N(n).map((function(e,n){return Object.keys(e.report).length>0?(0,q.jsxs)(Y.H,{children:[(0,q.jsx)(L.J,{isInline:!0,status:"success",children:(0,q.jsx)("img",{src:ne,alt:"Security Check Icon"})}),"\xa0",e.report.summary.remediations," remediations are available from Red Hat for ",e.provider]}):(0,q.jsxs)(Y.H,{children:[(0,q.jsx)(L.J,{isInline:!0,status:"success",children:(0,q.jsx)("img",{src:ne,alt:"Security Check Icon"})}),"\xa0 There are no available Red Hat remediations for your SBOM at this time for ",e.provider]})}))})})})]})}),"\xa0"]}),(0,q.jsxs)(o.P,{md:6,children:[(0,q.jsx)(E.Z,{isFlat:!0,children:(0,q.jsxs)(H.g,{children:[(0,q.jsx)(R.l,{component:"h4",children:(0,q.jsx)(F.M,{style:{fontSize:"large"},children:"Join to explore Red Hat TPA"})}),(0,q.jsx)(_.e,{children:(0,q.jsx)(G.b,{children:(0,q.jsxs)(V.aV,{isPlain:!0,children:[(0,q.jsx)(Y.H,{children:"Check out our new Trusted Profile Analyzer to get visibility and insight into your software risk profile, for instance by exploring vulnerabilites or analyzing SBOMs."}),(0,q.jsx)(Y.H,{children:(0,q.jsx)("a",{href:"https://console.redhat.com/application-services/trusted-content",target:"_blank",rel:"noopener noreferrer",children:(0,q.jsx)(J.zx,{variant:"primary",size:"sm",children:"Take me there"})})})]})})})]})}),"\xa0"]})]})},ie=r(2933),te=function(e){var n=e.report,r=Object.keys(n.providers).map((function(e){return n.providers[e].status})).filter((function(e){return!e.ok&&!(!(n=e).ok&&401===n.code&&"Unauthenticated"===n.message&&x.includes(n.name));var n}));return(0,q.jsx)(q.Fragment,{children:r.map((function(e,n){return(0,q.jsx)(ie.b,{variant:e.code>=500?ie.U.danger:e.code>=400?ie.U.warning:void 0,title:"".concat(M(e.name),": ").concat(e.message)},n)}))})},ae=r(74165),se=r(15861),oe=r(70885),ce=r(66081),le=r(74817),de=r(86467),ue=r(1413),he=r(19809),ge=r(80382),ve=r(88521),pe=r(82e3),xe=r(76989),je=r(52401),fe=r(96496),me=r(38987),ye=r(69623),Ie=r(29626),be=r(30205),Ce=r(73610),Me=r(27990),Te=r(75091),Ae=r(46056),Se=r(31915),we=r(71178),De=r(7102),Ne=r(42982),Pe=r(41917),ke=function(e){return e[e.SET_PAGE=0]="SET_PAGE",e[e.SET_SORT_BY=1]="SET_SORT_BY",e}(ke||{}),Oe={changed:!1,currentPage:{page:1,perPage:10},sortBy:void 0},Ze=function(e,n){switch(n.type){case ke.SET_PAGE:var r=n.payload;return(0,ue.Z)((0,ue.Z)({},e),{},{changed:!0,currentPage:{page:r.page,perPage:r.perPage}});case ke.SET_SORT_BY:var i=n.payload;return(0,ue.Z)((0,ue.Z)({},e),{},{changed:!0,sortBy:{index:i.index,direction:i.direction}});default:return e}},Le=r(99960),ze=r(50500),Ee=function(e){var n,r=e.count,i=e.params,t=e.isTop,a=(e.isCompact,e.perPageOptions),s=e.onChange,o=function(){return i.perPage||10};return(0,q.jsx)(Le.t,{itemCount:r,page:i.page||1,perPage:o(),onPageInput:function(e,n){s({page:n,perPage:o()})},onSetPage:function(e,n){s({page:n,perPage:o()})},onPerPageSelect:function(e,n){s({page:1,perPage:n})},widgetId:"pagination-options-menu",variant:t?Le.a.top:Le.a.bottom,perPageOptions:(n=a||[10,20,50,100],n.map((function(e){return{title:String(e),value:e}}))),toggleTemplate:function(e){return(0,q.jsx)(ze.v,(0,ue.Z)({},e))}})},Be=function(e){var n=e.name,r=e.showVersion,i=void 0!==r&&r;return(0,q.jsx)(q.Fragment,{children:(0,q.jsx)("a",{href:I(n),target:"_blank",rel:"noreferrer",children:m(n,i)})})},Re=r(70164),Fe=r(35020),_e=r(98649),He=r(37514),Ge=function(e){var n=e.numRenderedColumns,r=e.isLoading,i=void 0!==r&&r,t=e.isError,a=void 0!==t&&t,s=e.isNoData,o=void 0!==s&&s,c=e.errorEmptyState,l=void 0===c?null:c,d=e.noDataEmptyState,u=void 0===d?null:d,h=e.children,g=(0,q.jsxs)(he.u,{variant:he.I.sm,children:[(0,q.jsx)(ve.k,{icon:_e.ZP,color:He.a.value}),(0,q.jsx)(Z.D,{headingLevel:"h2",size:"lg",children:"Unable to connect"}),(0,q.jsx)(pe.B,{children:"There was an error retrieving data. Check your connection and try again."})]}),v=(0,q.jsxs)(he.u,{variant:he.I.sm,children:[(0,q.jsx)(ve.k,{icon:Fe.ZP}),(0,q.jsx)(Z.D,{headingLevel:"h2",size:"lg",children:"No data available"}),(0,q.jsx)(pe.B,{children:"No data available to be shown here."})]});return(0,q.jsx)(q.Fragment,{children:i?(0,q.jsx)(Ae.p,{children:(0,q.jsx)(Me.Tr,{children:(0,q.jsx)(Se.Td,{colSpan:n,children:(0,q.jsx)(Q.b,{children:(0,q.jsx)(Re.$,{size:"xl"})})})})}):a?(0,q.jsx)(Ae.p,{"aria-label":"Table error",children:(0,q.jsx)(Me.Tr,{children:(0,q.jsx)(Se.Td,{colSpan:n,children:(0,q.jsx)(Q.b,{children:l||g})})})}):o?(0,q.jsx)(Ae.p,{"aria-label":"Table no data",children:(0,q.jsx)(Me.Tr,{children:(0,q.jsx)(Se.Td,{colSpan:n,children:(0,q.jsx)(Q.b,{children:u||v})})})}):h})},Ue=function(e){var n=e.packageName;e.cves;return(0,q.jsxs)(q.Fragment,{children:[(0,q.jsx)(L.J,{isInline:!0,status:"success",children:(0,q.jsx)("img",{src:ne,alt:"Security Check Icon"})}),"\xa0",(0,q.jsx)("a",{href:y(n),target:"_blank",rel:"noreferrer",children:b(n)})]})},Ve=function(){var e=jn().providerPrivateData;return{hideIssue:function(n,r){return!(!e||-1===e.indexOf(n))&&r}}},Ye=function(e){var n,r,i,t=e.sourceName,a=e.vulnerability,s=Ve(),o=jn();return(0,q.jsx)(q.Fragment,{children:s.hideIssue(t,a.unique)?(0,q.jsxs)(q.Fragment,{children:[(0,q.jsx)("a",{href:o.snykSignup,target:"_blank",rel:"noreferrer",children:"Sign up for a Snyk account"})," ","to learn about the vulnerabilities found"]}):"snyk"!==t||null!==(null===(n=a.remediation)||void 0===n?void 0:n.fixedIn)&&0!==(null===(r=a.remediation)||void 0===r||null===(i=r.fixedIn)||void 0===i?void 0:i.length)?(0,q.jsx)("a",{href:C(t,a.id,o),target:"_blank",rel:"noreferrer",children:a.id}):(0,q.jsx)("p",{})})},Je=r(30736),We=r(75351),Qe=r(30975),Ke=r(6647),qe=function(e){var n,r=e.vulnerability;switch(r.severity){case"CRITICAL":case"HIGH":n=Je.n9.danger;break;default:n=Je.n9.warning}return(0,q.jsx)(q.Fragment,{children:(0,q.jsx)(We.P,{hasGutter:!0,children:(0,q.jsx)(Qe.J,{isFilled:!0,children:(0,q.jsx)(Ke.E,{title:"".concat(r.cvssScore,"/10"),"aria-label":"cvss-score",value:r.cvssScore,min:0,max:10,size:Ke.L.sm,variant:n,measureLocation:Je.nK.none})})})})},Xe=r(30313),$e=function(e){var n,r=e.vulnerability;switch(r.severity){case"CRITICAL":n="#800000";break;case"HIGH":n="#FF0000";break;case"MEDIUM":n="#FFA500";break;case"LOW":n="#5BA352";break;default:n="grey"}return(0,q.jsxs)(q.Fragment,{children:[(0,q.jsx)(L.J,{isInline:!0,children:(0,q.jsx)(Xe.ZP,{style:{fill:n,height:"13px"}})}),"\xa0",M(r.severity)]})},en=function(e){var n,r,i=e.id,t=jn();return(0,q.jsx)("a",{href:(n=i,r=t,r.cveIssueTemplate.replace(v,n)),target:"_blank",rel:"noreferrer",children:i})},nn=r(84150),rn=function(e){var n=e.title,r=i.useState(!1),t=(0,oe.Z)(r,2),a=t[0],s=t[1];return(0,q.jsx)(nn.L,{variant:nn.S.truncate,toggleText:a?"Show less":"Show more",onToggle:function(e,n){s(n)},isExpanded:a,children:n})},tn=function(e){var n,r,i,t,a,s=e.item,o=e.providerName,c=e.rowIndex;a=s.vulnerability.cves&&s.vulnerability.cves.length>0?s.vulnerability.cves:[s.vulnerability.id];var l=Ve().hideIssue(o,s.vulnerability.unique),d=jn();return(0,q.jsxs)(Me.Tr,{children:[l?(0,q.jsx)(q.Fragment,{children:(0,q.jsx)(Se.Td,{colSpan:3,children:(0,q.jsx)("a",{href:d.snykSignup,target:"_blank",rel:"noreferrer",children:"Sign up for a Snyk account to learn about the vulnerabilities found"})})}):(0,q.jsxs)(q.Fragment,{children:[(0,q.jsx)(Se.Td,{children:a.map((function(e,n){return(0,q.jsx)("p",{children:(0,q.jsx)(en,{id:e})},n)}))}),(0,q.jsx)(Se.Td,{children:(0,q.jsx)(rn,{title:s.vulnerability.title})}),(0,q.jsx)(Se.Td,{noPadding:!0,children:(0,q.jsx)($e,{vulnerability:s.vulnerability})})]}),(0,q.jsx)(Se.Td,{children:(0,q.jsx)(qe,{vulnerability:s.vulnerability})}),(0,q.jsx)(Se.Td,{children:(0,q.jsx)(Be,{name:s.dependencyRef,showVersion:!0})}),(0,q.jsx)(Se.Td,{children:null!==(n=s.vulnerability.remediation)&&void 0!==n&&n.trustedContent?(0,q.jsx)(Ue,{cves:s.vulnerability.cves||[],packageName:null===(r=s.vulnerability.remediation)||void 0===r||null===(i=r.trustedContent)||void 0===i?void 0:i.ref},c):null!==(t=s.vulnerability.remediation)&&void 0!==t&&t.fixedIn?(0,q.jsx)(Ye,{sourceName:o,vulnerability:s.vulnerability}):k(s.vulnerability)?null:(0,q.jsx)("span",{})})]},c)},an=function(e){var n=e.providerName,r=e.transitiveDependencies;return(0,q.jsx)(E.Z,{style:{backgroundColor:"var(--pf-v5-global--BackgroundColor--100)"},children:(0,q.jsxs)(Ie.i,{variant:be.B.compact,children:[(0,q.jsx)(Ce.h,{children:(0,q.jsxs)(Me.Tr,{children:[(0,q.jsx)(Te.Th,{width:15,children:"Vulnerability ID"}),(0,q.jsx)(Te.Th,{width:20,children:"Description"}),(0,q.jsx)(Te.Th,{width:10,children:"Severity"}),(0,q.jsx)(Te.Th,{width:15,children:"CVSS Score"}),(0,q.jsx)(Te.Th,{width:20,children:"Transitive Dependency"}),(0,q.jsx)(Te.Th,{width:20,children:"Remediation"})]})}),(0,q.jsx)(Ge,{isNoData:0===r.length,numRenderedColumns:7,children:O(r).map((function(e,r){return(0,q.jsx)(Ae.p,{children:(0,q.jsx)(tn,{item:e,providerName:n,rowIndex:r})},r)}))})]})})},sn=function(e){var n=e.providerName,r=e.dependency,i=e.vulnerabilities;return(0,q.jsx)(E.Z,{style:{backgroundColor:"var(--pf-v5-global--BackgroundColor--100)"},children:(0,q.jsxs)(Ie.i,{variant:be.B.compact,children:[(0,q.jsx)(Ce.h,{children:(0,q.jsxs)(Me.Tr,{children:[(0,q.jsx)(Te.Th,{width:15,children:"Vulnerability ID"}),(0,q.jsx)(Te.Th,{width:20,children:"Description"}),(0,q.jsx)(Te.Th,{width:10,children:"Severity"}),(0,q.jsx)(Te.Th,{width:15,children:"CVSS Score"}),(0,q.jsx)(Te.Th,{width:20,children:"Direct Dependency"}),(0,q.jsx)(Te.Th,{width:20,children:"Remediation"})]})}),(0,q.jsx)(Ge,{isNoData:0===i.length,numRenderedColumns:6,children:null===i||void 0===i?void 0:i.map((function(e,i){var t=[];return e.cves&&e.cves.length>0?e.cves.forEach((function(e){return t.push(e)})):e.unique&&t.push(e.id),(0,q.jsx)(Ae.p,{children:t.map((function(t,a){return(0,q.jsx)(tn,{item:{id:e.id,dependencyRef:r.ref,vulnerability:e},providerName:n,rowIndex:i},"".concat(i,"-").concat(a))}))},i)}))})]})})},on=r(63566),cn=function(e){var n=e.vulnerabilities,r=void 0===n?[]:n,i=e.transitiveDependencies,t=void 0===i?[]:i,a={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};return r.length>0?r.forEach((function(e){var n=e.severity;a.hasOwnProperty(n)&&a[n]++})):null===t||void 0===t||t.forEach((function(e){var n;null===(n=e.issues)||void 0===n||n.forEach((function(e){var n=e.severity;a.hasOwnProperty(n)&&a[n]++}))})),(0,q.jsxs)(on.B,{children:[a.CRITICAL>0&&(0,q.jsxs)(q.Fragment,{children:[(0,q.jsx)(L.J,{isInline:!0,children:(0,q.jsx)(Xe.ZP,{style:{fill:"#800000",height:"13px"}})}),"\xa0",a.CRITICAL,"\xa0"]}),a.HIGH>0&&(0,q.jsxs)(q.Fragment,{children:[(0,q.jsx)(L.J,{isInline:!0,children:(0,q.jsx)(Xe.ZP,{style:{fill:"#FF0000",height:"13px"}})}),"\xa0",a.HIGH,"\xa0"]}),a.MEDIUM>0&&(0,q.jsxs)(q.Fragment,{children:[(0,q.jsx)(L.J,{isInline:!0,children:(0,q.jsx)(Xe.ZP,{style:{fill:"#FFA500",height:"13px"}})}),"\xa0",a.MEDIUM,"\xa0"]}),a.LOW>0&&(0,q.jsxs)(q.Fragment,{children:[(0,q.jsx)(L.J,{isInline:!0,children:(0,q.jsx)(Xe.ZP,{style:{fill:"#5BA352",height:"13px"}})}),"\xa0",a.LOW]})]})},ln=r(56934),dn=function(e){var n,r,i=e.dependency,t=null===(n=i.issues)||void 0===n?void 0:n.some((function(e){return k(e)})),a=(null===(r=i.transitive)||void 0===r?void 0:r.some((function(e){var n;return null===(n=e.issues)||void 0===n?void 0:n.some((function(e){return k(e)}))})))||!1;return(0,q.jsx)(q.Fragment,{children:t||a?"Yes":"No"})},un=function(e){var n=e.name,r=e.dependencies,t=(0,i.useState)(""),a=(0,oe.Z)(t,2),s=a[0],o=a[1],c=function(e){var n=(0,i.useReducer)(Ze,(0,ue.Z)((0,ue.Z)({},Oe),{},{currentPage:e&&e.page?(0,ue.Z)({},e.page):(0,ue.Z)({},Oe.currentPage),sortBy:e&&e.sortBy?(0,ue.Z)({},e.sortBy):Oe.sortBy})),r=(0,oe.Z)(n,2),t=r[0],a=r[1],s=(0,i.useCallback)((function(e){var n;a({type:ke.SET_PAGE,payload:{page:e.page>=1?e.page:1,perPage:null!==(n=e.perPage)&&void 0!==n?n:Oe.currentPage.perPage}})}),[]),o=(0,i.useCallback)((function(e,n,r,i){a({type:ke.SET_SORT_BY,payload:{index:n,direction:r}})}),[]);return{page:t.currentPage,sortBy:t.sortBy,changePage:s,changeSortBy:o}}(),l=c.page,d=c.sortBy,u=c.changePage,h=c.changeSortBy,g=function(e){var n=e.items,r=e.currentSortBy,t=e.currentPage,a=e.filterItem,s=e.compareToByColumn;return(0,i.useMemo)((function(){var e,i=(0,Ne.Z)(n||[]).filter(a),o=!1;return e=(0,Ne.Z)(i).sort((function(e,n){var i=s(e,n,null===r||void 0===r?void 0:r.index);return 0!==i&&(o=!0),i})),o&&(null===r||void 0===r?void 0:r.direction)===Pe.B.desc&&(e=e.reverse()),{pageItems:e.slice((t.page-1)*t.perPage,t.page*t.perPage),filteredItems:i}}),[n,t,r,s,a])}({items:r,currentPage:l,currentSortBy:d,compareToByColumn:function(e,n,r){return 1===r?e.ref.localeCompare(n.ref):0},filterItem:function(e){var n=!0;return s&&s.trim().length>0&&(n=-1!==e.ref.toLowerCase().indexOf(s.toLowerCase())),n}}),v=g.pageItems,p=g.filteredItems,x={name:"Dependency Name",version:"Current Version",direct:"Direct Vulnerabilities",transitive:"Transitive Vulnerabilities",rhRemediation:"Remediation available"},j=i.useState({"siemur/test-space":"name"}),m=(0,oe.Z)(j,2),y=m[0],I=m[1],C=function(e,n,r,i){return{isExpanded:y[e.ref]===n,onToggle:function(){return function(e,n){var r=!(arguments.length>2&&void 0!==arguments[2])||arguments[2],i=(0,ue.Z)({},y);r?i[e.ref]=n:delete i[e.ref],I(i)}(e,n,y[e.ref]!==n)},expandId:"compound-expandable-example",rowIndex:r,columnIndex:i}};return(0,q.jsx)(E.Z,{children:(0,q.jsx)(_.e,{children:(0,q.jsx)("div",{style:{backgroundColor:"var(--pf-v5-global--BackgroundColor--100)"},children:""!==f(n)&&void 0===r?(0,q.jsx)("div",{children:(0,q.jsxs)(he.u,{variant:he.I.sm,children:[(0,q.jsx)(ge.t,{icon:(0,q.jsx)(ve.k,{icon:Fe.ZP}),titleText:"Set up "+n,headingLevel:"h2"}),(0,q.jsxs)(pe.B,{children:["You need to provide a valid credentials to see ",n," data. You can use the button below to sing-up for ",n,". If you have already signed up, enter your credentials in your extension settings and then regenerate the Dependency Analytics report."]}),(0,q.jsx)("br",{}),(0,q.jsx)("br",{}),(0,q.jsx)("a",{href:f(n),target:"_blank",rel:"noopener noreferrer",children:(0,q.jsxs)(J.zx,{variant:"primary",size:"sm",children:["Sign up for ",n]})})]})}):(0,q.jsxs)(q.Fragment,{children:[(0,q.jsx)(xe.o,{children:(0,q.jsxs)(je.c,{children:[(0,q.jsx)(fe.R,{toggleIcon:(0,q.jsx)(De.ZP,{}),breakpoint:"xl",children:(0,q.jsx)(me.E,{variant:"search-filter",children:(0,q.jsx)(ye.M,{style:{width:"250px"},placeholder:"Filter by Dependency name",value:s,onChange:function(e,n){return o(n)},onClear:function(){return o("")}})})}),(0,q.jsx)(me.E,{variant:me.A.pagination,align:{default:"alignRight"},children:(0,q.jsx)(Ee,{isTop:!0,count:p.length,params:l,onChange:u})})]})}),(0,q.jsxs)(Ie.i,{"aria-label":"Compound expandable table",variant:be.B.compact,children:[(0,q.jsx)(Ce.h,{children:(0,q.jsxs)(Me.Tr,{children:[(0,q.jsx)(Te.Th,{width:25,sort:{columnIndex:1,sortBy:(0,ue.Z)({},d),onSort:h},children:x.name}),(0,q.jsx)(Te.Th,{children:x.version}),(0,q.jsx)(Te.Th,{children:x.direct}),(0,q.jsx)(Te.Th,{children:x.transitive}),(0,q.jsx)(Te.Th,{children:x.rhRemediation})]})}),(0,q.jsx)(Ge,{isNoData:0===p.length,numRenderedColumns:8,noDataEmptyState:(0,q.jsxs)(he.u,{variant:he.I.sm,children:[(0,q.jsx)(ge.t,{icon:(0,q.jsx)(ve.k,{icon:ln.ZP}),titleText:"No results found",headingLevel:"h2"}),(0,q.jsx)(pe.B,{children:"Clear all filters and try again."})]}),children:null===v||void 0===v?void 0:v.map((function(e,r){var i,t,a,s,o,c=y[e.ref],l=!!c;return null!==(i=e.issues)&&void 0!==i&&i.length||null!==(t=e.transitive)&&void 0!==t&&t.length?(0,q.jsxs)(Ae.p,{isExpanded:l,children:[(0,q.jsxs)(Me.Tr,{children:[(0,q.jsx)(Se.Td,{width:30,dataLabel:x.name,component:"th",children:(0,q.jsx)(Be,{name:e.ref})}),(0,q.jsx)(Se.Td,{width:15,dataLabel:x.version,children:b(e.ref)}),(0,q.jsx)(Se.Td,{width:15,dataLabel:x.direct,compoundExpand:C(e,"direct",r,2),children:null!==(a=e.issues)&&void 0!==a&&a.length?(0,q.jsxs)("div",{style:{display:"flex",alignItems:"center"},children:[(0,q.jsx)("div",{style:{width:"25px"},children:null===(s=e.issues)||void 0===s?void 0:s.length}),(0,q.jsx)(z.i,{orientation:{default:"vertical"},style:{paddingRight:"10px"}}),(0,q.jsx)(cn,{vulnerabilities:e.issues})]}):0}),(0,q.jsx)(Se.Td,{width:15,dataLabel:x.transitive,compoundExpand:C(e,"transitive",r,3),children:null!==(o=e.transitive)&&void 0!==o&&o.length?(0,q.jsxs)("div",{style:{display:"flex",alignItems:"center"},children:[(0,q.jsx)("div",{style:{width:"25px"},children:e.transitive.map((function(e){var n;return null===(n=e.issues)||void 0===n?void 0:n.length})).reduce((function(){return(arguments.length>0&&void 0!==arguments[0]?arguments[0]:0)+(arguments.length>1&&void 0!==arguments[1]?arguments[1]:0)}))}),(0,q.jsx)(z.i,{orientation:{default:"vertical"},style:{paddingRight:"10px"}}),(0,q.jsx)(cn,{transitiveDependencies:e.transitive})]}):0}),(0,q.jsx)(Se.Td,{width:15,dataLabel:x.rhRemediation,children:(0,q.jsx)(dn,{dependency:e})})]}),l?(0,q.jsx)(Me.Tr,{isExpanded:l,children:(0,q.jsx)(Se.Td,{dataLabel:x[c],noPadding:!0,colSpan:6,children:(0,q.jsx)(we.G,{children:(0,q.jsx)("div",{className:"pf-v5-u-m-md",children:"direct"===c&&e.issues&&e.issues.length>0?(0,q.jsx)(sn,{providerName:n,dependency:e,vulnerabilities:e.issues}):"transitive"===c&&e.transitive&&e.transitive.length>0?(0,q.jsx)(an,{providerName:n,transitiveDependencies:e.transitive}):null})})})}):null]},e.ref):null}))})]}),(0,q.jsx)(Ee,{isTop:!1,count:p.length,params:l,onChange:u}),"osv-nvd"===n&&(0,q.jsx)("div",{children:(0,q.jsx)("p",{children:"Disclaimer:This Product uses data from the NVD API but is not endorsed or certified by the NVD"})})]})})})})},hn=r(61602),gn=function(e){var n=e.report,r=jn(),t=N(n),s=i.useState(P(t[0])),o=(0,oe.Z)(s,2),c=o[0],l=o[1],d=i.useState(!0),u=(0,oe.Z)(d,1)[0],h=r.writeKey&&""!==r.writeKey.trim()?hn.b.load({writeKey:r.writeKey}):null,g=(0,i.useRef)(""),v=(0,i.useRef)(!1);(0,i.useEffect)((function(){h&&!v.current&&(null!=r.userId?h.identify(r.userId):null!=r.anonymousId&&h.setAnonymousId(r.anonymousId),v.current=!0)}),[]),(0,i.useEffect)((function(){if(h){var e=function(){var e=(0,se.Z)((0,ae.Z)().mark((function e(n){return(0,ae.Z)().wrap((function(e){for(;;)switch(e.prev=e.next){case 0:n!==g.current&&(h.track("rhda.exhort.tab",{tabName:n}),g.current=n);case 1:case"end":return e.stop()}}),e)})));return function(n){return e.apply(this,arguments)}}();e(c)}}),[c,h]);var p=t.map((function(e){var n,r=P(e),i=null===(n=e.report.dependencies)||void 0===n?void 0:n.filter((function(e){return e.highestVulnerability}));return(0,q.jsx)(ce.O,{eventKey:r,title:(0,q.jsx)(le.T,{children:r}),"aria-label":"".concat(r," source"),children:(0,q.jsx)(a.NP,{variant:a.Dk.default,children:(0,q.jsx)(un,{name:r,dependencies:i})})})}));return(0,q.jsx)("div",{children:(0,q.jsx)(de.m,{activeKey:c,onSelect:function(e,n){l(n)},"aria-label":"Providers",role:"region",variant:u?"light300":"default",isBox:!0,children:p})})},vn=function(e){var n=e.report,r=i.useState(Object.keys(n)[0]||""),t=(0,oe.Z)(r,2),c=t[0],l=t[1],d=i.useState(!0),u=(0,oe.Z)(d,1)[0],h=Object.entries(n).map((function(e){var n=(0,oe.Z)(e,2),r=n[0],i=n[1];return(0,q.jsxs)(ce.O,{eventKey:r,title:(0,q.jsx)(le.T,{children:T(r)}),"aria-label":"".concat(r," source"),children:[(0,q.jsx)(te,{report:i}),(0,q.jsx)(a.NP,{variant:a.Dk.light,children:(0,q.jsx)(s.r,{hasGutter:!0,children:(0,q.jsx)(o.P,{children:(0,q.jsx)(re,{report:i,isReportMap:!0,purl:r})})})}),(0,q.jsx)(a.NP,{variant:a.Dk.default,children:(0,q.jsx)(gn,{report:i})})]})}));return(0,q.jsx)("div",{children:(0,q.jsx)(de.m,{activeKey:c,onSelect:function(e,n){l(n)},"aria-label":"Providers",role:"region",variant:u?"light300":"default",isBox:!0,children:h})})},pn=window.appData,xn=(0,i.createContext)(pn),jn=function(){return(0,i.useContext)(xn)};var fn=function(){return(0,q.jsx)(xn.Provider,{value:pn,children:(e=pn.report,"object"===typeof e&&null!==e&&Object.keys(e).every((function(n){return"scanned"in e[n]&&"providers"in e[n]&&"object"===typeof e[n].scanned&&"object"===typeof e[n].providers}))?(0,q.jsx)(a.NP,{variant:a.Dk.default,children:(0,q.jsx)(vn,{report:pn.report})}):(0,q.jsxs)(q.Fragment,{children:[(0,q.jsx)(te,{report:pn.report}),(0,q.jsx)(a.NP,{variant:a.Dk.light,children:(0,q.jsx)(s.r,{hasGutter:!0,children:(0,q.jsx)(o.P,{children:(0,q.jsx)(re,{report:pn.report})})})}),(0,q.jsx)(a.NP,{variant:a.Dk.default,children:(0,q.jsx)(gn,{report:pn.report})})]}))});var e},mn=function(e){e&&e instanceof Function&&r.e(736).then(r.bind(r,40599)).then((function(n){var r=n.getCLS,i=n.getFID,t=n.getFCP,a=n.getLCP,s=n.getTTFB;r(e),i(e),t(e),a(e),s(e)}))};t.createRoot(document.getElementById("root")).render((0,q.jsx)(i.StrictMode,{children:(0,q.jsx)(fn,{})})),mn()}},n={};function r(i){var t=n[i];if(void 0!==t)return t.exports;var a=n[i]={id:i,loaded:!1,exports:{}};return e[i].call(a.exports,a,a.exports,r),a.loaded=!0,a.exports}r.m=e,function(){var e=[];r.O=function(n,i,t,a){if(!i){var s=1/0;for(d=0;d<e.length;d++){i=e[d][0],t=e[d][1],a=e[d][2];for(var o=!0,c=0;c<i.length;c++)(!1&a||s>=a)&&Object.keys(r.O).every((function(e){return r.O[e](i[c])}))?i.splice(c--,1):(o=!1,a<s&&(s=a));if(o){e.splice(d--,1);var l=t();void 0!==l&&(n=l)}}return n}a=a||0;for(var d=e.length;d>0&&e[d-1][2]>a;d--)e[d]=e[d-1];e[d]=[i,t,a]}}(),r.n=function(e){var n=e&&e.__esModule?function(){return e.default}:function(){return e};return r.d(n,{a:n}),n},function(){var e,n=Object.getPrototypeOf?function(e){return Object.getPrototypeOf(e)}:function(e){return e.__proto__};r.t=function(i,t){if(1&t&&(i=this(i)),8&t)return i;if("object"===typeof i&&i){if(4&t&&i.__esModule)return i;if(16&t&&"function"===typeof i.then)return i}var a=Object.create(null);r.r(a);var s={};e=e||[null,n({}),n([]),n(n)];for(var o=2&t&&i;"object"==typeof o&&!~e.indexOf(o);o=n(o))Object.getOwnPropertyNames(o).forEach((function(e){s[e]=function(){return i[e]}}));return s.default=function(){return i},r.d(a,s),a}}(),r.d=function(e,n){for(var i in n)r.o(n,i)&&!r.o(e,i)&&Object.defineProperty(e,i,{enumerable:!0,get:n[i]})},r.e=function(){return Promise.resolve()},r.g=function(){if("object"===typeof globalThis)return globalThis;try{return this||new Function("return this")()}catch(e){if("object"===typeof window)return window}}(),r.o=function(e,n){return Object.prototype.hasOwnProperty.call(e,n)},r.r=function(e){"undefined"!==typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},r.nmd=function(e){return e.paths=[],e.children||(e.children=[]),e},function(){var e={179:0};r.O.j=function(n){return 0===e[n]};var n=function(n,i){var t,a,s=i[0],o=i[1],c=i[2],l=0;if(s.some((function(n){return 0!==e[n]}))){for(t in o)r.o(o,t)&&(r.m[t]=o[t]);if(c)var d=c(r)}for(n&&n(i);l<s.length;l++)a=s[l],r.o(e,a)&&e[a]&&e[a][0](),e[a]=0;return r.O(d)},i=self.webpackChunkui=self.webpackChunkui||[];i.forEach(n.bind(null,0)),i.push=n.bind(null,i.push.bind(i))}();var i=r.O(void 0,[736],(function(){return r(31958)}));i=r.O(i)}();