!function(){"use strict";var e={31958:function(e,n,r){var i=r(68963),t=r(63609),a=(r(13218),r(19559)),s=r(39714),o=r(34187),c=r(15671),l=r(43144),d="maven",u="https://pkg.go.dev/",h="https://www.npmjs.com/package/",g="https://pypi.org/project/",v="__ISSUE_ID__",p="pkg:",x=["oss-index"],j="https://maven.repository.redhat.com/ga/",f=/%[0-9A-Fa-f]{2}/,m=function(e){return"oss-index"===e?"https://ossindex.sonatype.org/user/register":""},y=function(e,n){var r=N.fromString(e),i=function(e){var n="";return e.namespace&&(n=e.type===d?"".concat(e.namespace,":"):"".concat(e.namespace,"/")),n+"".concat(e.name)}(r);return n?i+"@".concat(r.version):i},I=function(e){var n=N.fromString(e),r=j;if(n.namespace){var i,t=null===(i=n.namespace)||void 0===i?void 0:i.replace(/\./g,"/");return"".concat(j).concat(t,"/").concat(n.name,"/").concat(n.version)}return r},b=function(e){var n=N.fromString(e);switch(n.type){case d:var r=n.version;if(null!==r&&void 0!==r&&r.includes("redhat")){var i,t=null===(i=n.namespace)||void 0===i?void 0:i.replace(/\./g,"/");return"".concat(j).concat(t,"/").concat(n.name,"/").concat(n.version)}return"".concat("https://central.sonatype.com/artifact/").concat(n.namespace,"/").concat(n.name,"/").concat(n.version);case"golang":var a=n.version;return null!==a&&void 0!==a&&a.match(/v\d\.\d.\d-\d{14}-\w{12}/)?"".concat(u).concat(n.namespace,"/").concat(n.name):"".concat(u).concat(n.namespace,"/").concat(n.name,"@").concat(n.version);case"npm":return n.namespace?"".concat(h).concat(n.namespace,"/").concat(n.name,"/v/").concat(n.version):"".concat(h).concat(n.name,"/v/").concat(n.version);case"pypi":return n.namespace?"".concat(g).concat(n.namespace,"/").concat(n.name,"/").concat(n.version):"".concat(g).concat(n.name,"/").concat(n.version);default:return n.toString()}},C=function(e){var n=N.fromString(e).version;return n||""},M=function(e,n,r){switch(e){case"snyk":return r.snykIssueTemplate.replace(v,n);case"oss-index":return r.ossIssueTemplate.replace(v,n);case"osv-nvd":return r.nvdIssueTemplate.replace(v,n)}},T=function(e){return e.toLowerCase().replace(/./,(function(e){return e.toUpperCase()}))},A=function(e){var n=S(e),r="";if(n.repository_url){var i=n.repository_url.indexOf("/");r+=-1!==i?n.repository_url.substring(i+1):""}else r+="".concat(n.short_name);return n.tag&&(r+=":".concat(n.tag)),r},S=function(e){var n=e.split("?"),r=n[0],i=n[1],t=new URLSearchParams(i),a=t.get("repository_url")||"",s=t.get("tag")||"",o=t.get("arch")||"",c=r.split("@");return{repository_url:a,tag:s,short_name:c[0].substring(c[0].indexOf("/")+1),version:r.substring(r.lastIndexOf("@")).replace("%3A",":"),arch:o}},w=function(e,n,r){var i=P(n);for(var t in i){var a=i[t].report.dependencies;if(a){var s=Object.values(a).find((function(n){var r,i=n.ref,t=decodeURIComponent(i),a=(r=e,f.test(r)?decodeURIComponent(e):e);return N.fromString(t).toString()===N.fromString(a).toString()}));if(s&&s.recommendation){var o=decodeURIComponent(s.recommendation),c=D(o,r);if(void 0!==c)return c}}}return"https://catalog.redhat.com/software/containers/search"},D=function(e,n){var r=JSON.parse(n).find((function(n){return N.fromString(n.purl).toString()===N.fromString(e).toString()}));return null===r||void 0===r?void 0:r.catalogUrl},N=function(){function e(n,r,i,t){(0,c.Z)(this,e),this.type=void 0,this.namespace=void 0,this.name=void 0,this.version=void 0,this.type=n,this.namespace=r,this.name=i,this.version=t}return(0,l.Z)(e,[{key:"toString",value:function(){var e=this.name;return this.version&&(e+="@".concat(this.version)),this.namespace?"".concat(p).concat(this.type,"/").concat(this.namespace,"/").concat(e):"".concat(p).concat(this.type,"/").concat(e)}}],[{key:"fromString",value:function(n){var r=n.replace(p,""),i=r.indexOf("?");-1!==i&&(r=r.substring(0,i));var t,a,s=r.substring(0,r.indexOf("/")),o=r.split("/");o.length>2&&(t=o.slice(1,o.length-1).join("/")),-1!==r.indexOf("@")&&(a=r.substring(r.indexOf("@")+1));var c=o[o.length-1];return a&&(c=c.substring(0,c.indexOf("@"))),new e(s,t,c,a)}}]),e}();function P(e){var n=[];return Object.keys(e.providers).forEach((function(r){var i=e.providers[r].sources;void 0!==i&&Object.keys(i).length>0?Object.keys(i).forEach((function(e){n.push({provider:r,source:e,report:i[e]})})):"trusted-content"!==r&&n.push({provider:r,source:r,report:{}})})),n.sort((function(e,n){return 0===Object.keys(e.report).length&&0===Object.keys(n.report).length?""===m(e.provider)?""===m(n.provider)?0:-1:1:Object.keys(n.report).length-Object.keys(e.report).length}))}function k(e){return void 0===e?"unknown":e.provider!==e.source?"$item.provider/$item.source":e.provider}function O(e){var n;return!(!e.remediation||!(e.remediation.fixedIn||null!==(n=e.remediation)&&void 0!==n&&n.trustedContent))}function Z(e){var n=[];return e.map((function(e){return{dependencyRef:e.ref,vulnerabilities:e.issues||[]}})).forEach((function(e){var r;null===(r=e.vulnerabilities)||void 0===r||r.forEach((function(r){r.cves&&r.cves.length>0?r.cves.forEach((function(i){n.push({id:i,dependencyRef:e.dependencyRef,vulnerability:r})})):n.push({id:r.id,dependencyRef:e.dependencyRef,vulnerability:r})}))})),n.sort((function(e,n){return n.vulnerability.cvssScore-e.vulnerability.cvssScore}))}var L=r(43442),z=r(73324),E=r(96363),B=r(78437),R=r(26798),F=r(62996),_=r(73020),H=r(34223),U=r(11858),G=r(90493),V=r(47065),Y=r(17941),J=r(82355),W=r(38485),Q=r(29090),K=r(2570),q=r(22124),X=r(75859),$=["#800000","#FF0000","#FFA500","#5BA352"],ee=function(e){var n,r,i,t,a,s=e.summary,o=null!==(n=null===s||void 0===s?void 0:s.critical)&&void 0!==n?n:0,c=null!==(r=null===s||void 0===s?void 0:s.high)&&void 0!==r?r:0,l=null!==(i=null===s||void 0===s?void 0:s.medium)&&void 0!==i?i:0,d=null!==(t=null===s||void 0===s?void 0:s.low)&&void 0!==t?t:0,u=null!==(a=null===s||void 0===s?void 0:s.total)&&void 0!==a?a:0,h=o+c+l+d>0,g=h?$:["#D5F5E3"],v=[{name:"Critical: ".concat(o),symbol:{type:"square",fill:$[0]}},{name:"High: ".concat(c),symbol:{type:"square",fill:$[1]}},{name:"Medium: ".concat(l),symbol:{type:"square",fill:$[2]}},{name:"Low: ".concat(d),symbol:{type:"square",fill:$[3]}}];return(0,X.jsx)("div",{children:(0,X.jsx)(H.e,{style:{paddingBottom:"inherit",padding:"0"},children:(0,X.jsx)(K.b,{children:(0,X.jsx)("div",{style:{height:"230px",width:"350px"},children:(0,X.jsx)(q.H,{constrainToVisibleArea:!0,data:h?[{x:"Critical",y:o},{x:"High",y:c},{x:"Medium",y:l},{x:"Low",y:d}]:[{x:"Empty",y:1e-10}],labels:function(e){var n=e.datum;return"".concat(n.x,": ").concat(n.y)},legendData:v,legendOrientation:"vertical",legendPosition:"right",padding:{left:20,right:140},subTitle:"Unique vulnerabilities",title:"".concat(u),width:350,colorScale:g})})})})})},ne=r(66155),re="data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHN2ZyB3aWR0aD0iMTJweCIgaGVpZ2h0PSIxM3B4IiB2aWV3Qm94PSIwIDAgMTIgMTMiIGlkPSJTZWN1cml0eUNoZWNrSWNvbiIgdmVyc2lvbj0iMS4xIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIj4KICAgIDx0aXRsZT5Db21iaW5lZCBTaGFwZTwvdGl0bGU+CiAgICA8ZyBpZD0iTXVsdGktdmVuZG9yIiBzdHJva2U9Im5vbmUiIHN0cm9rZS13aWR0aD0iMSIgZmlsbD0ibm9uZSIgZmlsbC1ydWxlPSJldmVub2RkIj4KICAgICAgICA8ZyBpZD0iT3ZlcnZpZXctQ29weSIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoLTEyMDcsIC05OTMpIiBmaWxsPSIjM0U4NjM1Ij4KICAgICAgICAgICAgPGcgaWQ9IkRldGFpbHMtb2YtZGVwZW5kZW5jeS1jb20uZ2l0aHViIiB0cmFuc2Zvcm09InRyYW5zbGF0ZSg0MjcsIDgxOSkiPgogICAgICAgICAgICAgICAgPGcgaWQ9IkRlcGVuZGVuY3ktMSIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoMCwgMTQ0KSI+CiAgICAgICAgICAgICAgICAgICAgPGcgaWQ9Ikdyb3VwLTkiIHRyYW5zZm9ybT0idHJhbnNsYXRlKDc4MC4xNzI4LCAyNCkiPgogICAgICAgICAgICAgICAgICAgICAgICA8ZyBpZD0iR3JvdXAtNCIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoMCwgMy4yKSI+CiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZyBpZD0iSWNvbnMvMi4tU2l6ZS1zbS9BY3Rpb25zL2NoZWNrIiB0cmFuc2Zvcm09InRyYW5zbGF0ZSgwLCAyLjgpIj4KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8cGF0aCBkPSJNMTAuNTU2NTc4OSwwIEMxMC43OTA2MjQ5LDAgMTAuOTc5MzMyMiwwLjE4MTU0Mjk2OSAxMC45NzkzMzIyLDAuNDA2MjUgTDEwLjk3OTMzMjIsNS43NDA4MjAzMSBDMTAuOTc5MzMyMiw5Ljc1IDYuMjQwODE5MDcsMTMgNS40OTU3OTI5NiwxMyBDNC43NTA3NjY4NCwxMyAwLDkuNzUgMCw1LjczOTU1MDc4IEwwLDAuNDA2MjUgQzAsMC4xODE1NDI5NjkgMC4xODg3MDcyNzIsMCAwLjQyMjc1MzMwNCwwIFogTTguNTQyNzc4ODMsMy4xMTc4MjY2NyBMNC43OTEyOTYxLDYuODkwODczNTMgTDMuMDM5ODEzMzgsNS4xMjkzMjQ0IEMyLjg4MzYwOSw0Ljk3MjIwNjgzIDIuNjMwMzI4MTIsNC45NzIyMDY4MyAyLjQ3NDEyMzc1LDUuMTI5MzI0NCBMMS45MDg0NDkzOCw1LjY5ODI2NTU2IEMxLjc1MjI0NTAxLDUuODU1MzgzMTIgMS43NTIyNDUwMSw2LjExMDEwNDQ5IDEuOTA4NDQ5MzgsNi4yNjcyMDY3MSBMNC41MDg0NTc5Nyw4Ljg4MjE1OTkxIEM0LjY2NDY0NzA4LDkuMDM5Mjc3NDcgNC45MTc5MTI3LDkuMDM5Mjc3NDcgNS4wNzQxMzIzMyw4Ljg4MjE3NTI1IEw5LjY3NDE0MjgyLDQuMjU1NzA4OTggQzkuODMwMzQ3Miw0LjA5ODU5MTQxIDkuODMwMzQ3MiwzLjg0Mzg3MDA0IDkuNjc0MTQyODIsMy42ODY3Njc4MiBMOS4xMDg0Njg0NiwzLjExNzgyNjY3IEM4Ljk1MjI2NDA4LDIuOTYwNzI0NDQgOC42OTg5ODMyLDIuOTYwNzI0NDQgOC41NDI3Nzg4MywzLjExNzgyNjY3IFoiIGlkPSJDb21iaW5lZC1TaGFwZSI+PC9wYXRoPgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICAgICAgICAgICAgICA8L2c+CiAgICAgICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICA8L2c+CiAgICAgICAgPC9nPgogICAgPC9nPgo8L3N2Zz4=",ie=function(e){var n=e.report,r=e.isReportMap,i=e.purl,t=fn();return(0,X.jsxs)(s.r,{hasGutter:!0,children:[(0,X.jsxs)(L.D,{headingLevel:"h3",size:L.H["2xl"],style:{paddingLeft:"15px"},children:[(0,X.jsx)(z.J,{isInline:!0,status:"info",children:(0,X.jsx)(Q.ZP,{style:{fill:"#f0ab00"}})}),"\xa0Red Hat Overview of security Issues"]}),(0,X.jsx)(E.i,{}),(0,X.jsx)(o.P,{children:(0,X.jsxs)(B.Z,{isFlat:!0,isFullHeight:!0,children:[(0,X.jsx)(R.O,{children:(0,X.jsx)(F.l,{children:(0,X.jsx)(_.M,{style:{fontSize:"large"},children:r?(0,X.jsxs)(X.Fragment,{children:[i?A(i):"No Image name"," - Vendor Issues"]}):(0,X.jsx)(X.Fragment,{children:"Vendor Issues"})})})}),(0,X.jsxs)(H.e,{children:[(0,X.jsx)(U.g,{children:(0,X.jsx)(G.b,{children:(0,X.jsx)(_.M,{children:"Below is a list of dependencies affected with CVE."})})}),(0,X.jsx)(V.o,{isAutoFit:!0,style:{paddingTop:"10px"},children:P(n).map((function(e,n){return(0,X.jsxs)(U.g,{style:{display:"flex",flexDirection:"column",alignItems:"center"},children:[(0,X.jsx)(X.Fragment,{children:(0,X.jsx)(_.M,{style:{fontSize:"large"},children:k(e)})}),(0,X.jsx)(G.b,{children:(0,X.jsx)(ee,{summary:e.report.summary})})]},n)}))})]}),(0,X.jsx)(E.i,{})]})}),(0,X.jsxs)(o.P,{md:6,children:[(0,X.jsx)(B.Z,{isFlat:!0,children:(0,X.jsxs)(U.g,{children:[(0,X.jsx)(F.l,{component:"h4",children:(0,X.jsxs)(_.M,{style:{fontSize:"large"},children:[(0,X.jsx)(z.J,{isInline:!0,status:"info",children:(0,X.jsx)(ne.ZP,{style:{fill:"#cc0000"}})}),"\xa0 Red Hat Remediations"]})}),(0,X.jsx)(H.e,{children:(0,X.jsx)(G.b,{children:r?(0,X.jsxs)(Y.aV,{isPlain:!0,children:[(0,X.jsx)(J.H,{children:"Switch to UBI 9 for enhanced security and enterprise-grade stability in your containerized applications, backed by Red Hat's support and compatibility assurance."}),(0,X.jsx)(J.H,{children:(0,X.jsx)("a",{href:i?w(i,n,t.imageMapping):"###",target:"_blank",rel:"noreferrer",children:(0,X.jsx)(W.zx,{variant:"primary",size:"sm",children:"Take me there"})})})]}):(0,X.jsx)(Y.aV,{isPlain:!0,children:P(n).map((function(e,n){return Object.keys(e.report).length>0?(0,X.jsxs)(J.H,{children:[(0,X.jsx)(z.J,{isInline:!0,status:"success",children:(0,X.jsx)("img",{src:re,alt:"Security Check Icon"})}),"\xa0",e.report.summary.remediations," remediations are available from Red Hat for ",e.provider]}):(0,X.jsxs)(J.H,{children:[(0,X.jsx)(z.J,{isInline:!0,status:"success",children:(0,X.jsx)("img",{src:re,alt:"Security Check Icon"})}),"\xa0 There are no available Red Hat remediations for your SBOM at this time for ",e.provider]})}))})})})]})}),"\xa0"]}),(0,X.jsxs)(o.P,{md:6,children:[(0,X.jsx)(B.Z,{isFlat:!0,children:(0,X.jsxs)(U.g,{children:[(0,X.jsx)(F.l,{component:"h4",children:(0,X.jsx)(_.M,{style:{fontSize:"large"},children:"Join to explore Red Hat TPA"})}),(0,X.jsx)(H.e,{children:(0,X.jsx)(G.b,{children:(0,X.jsxs)(Y.aV,{isPlain:!0,children:[(0,X.jsx)(J.H,{children:"Check out our new Trusted Profile Analyzer to get visibility and insight into your software risk profile, for instance by exploring vulnerabilites or analyzing SBOMs."}),(0,X.jsx)(J.H,{children:(0,X.jsx)("a",{href:"https://console.redhat.com/application-services/trusted-content",target:"_blank",rel:"noopener noreferrer",children:(0,X.jsx)(W.zx,{variant:"primary",size:"sm",children:"Take me there"})})})]})})})]})}),"\xa0"]})]})},te=r(2933),ae=function(e){var n=e.report,r=Object.keys(n.providers).map((function(e){return n.providers[e].status})).filter((function(e){return!e.ok&&!(!(n=e).ok&&401===n.code&&"Unauthenticated"===n.message&&x.includes(n.name));var n}));return(0,X.jsx)(X.Fragment,{children:r.map((function(e,n){return(0,X.jsx)(te.b,{variant:e.code>=500?te.U.danger:e.code>=400?te.U.warning:void 0,title:"".concat(T(e.name),": ").concat(e.message)},n)}))})},se=r(74165),oe=r(15861),ce=r(70885),le=r(66081),de=r(74817),ue=r(86467),he=r(1413),ge=r(19809),ve=r(80382),pe=r(88521),xe=r(82e3),je=r(76989),fe=r(52401),me=r(96496),ye=r(38987),Ie=r(69623),be=r(29626),Ce=r(30205),Me=r(73610),Te=r(27990),Ae=r(75091),Se=r(46056),we=r(31915),De=r(71178),Ne=r(7102),Pe=r(42982),ke=r(41917),Oe=function(e){return e[e.SET_PAGE=0]="SET_PAGE",e[e.SET_SORT_BY=1]="SET_SORT_BY",e}(Oe||{}),Ze={changed:!1,currentPage:{page:1,perPage:10},sortBy:void 0},Le=function(e,n){switch(n.type){case Oe.SET_PAGE:var r=n.payload;return(0,he.Z)((0,he.Z)({},e),{},{changed:!0,currentPage:{page:r.page,perPage:r.perPage}});case Oe.SET_SORT_BY:var i=n.payload;return(0,he.Z)((0,he.Z)({},e),{},{changed:!0,sortBy:{index:i.index,direction:i.direction}});default:return e}},ze=r(99960),Ee=r(50500),Be=function(e){var n,r=e.count,i=e.params,t=e.isTop,a=(e.isCompact,e.perPageOptions),s=e.onChange,o=function(){return i.perPage||10};return(0,X.jsx)(ze.t,{itemCount:r,page:i.page||1,perPage:o(),onPageInput:function(e,n){s({page:n,perPage:o()})},onSetPage:function(e,n){s({page:n,perPage:o()})},onPerPageSelect:function(e,n){s({page:1,perPage:n})},widgetId:"pagination-options-menu",variant:t?ze.a.top:ze.a.bottom,perPageOptions:(n=a||[10,20,50,100],n.map((function(e){return{title:String(e),value:e}}))),toggleTemplate:function(e){return(0,X.jsx)(Ee.v,(0,he.Z)({},e))}})},Re=function(e){var n=e.name,r=e.showVersion,i=void 0!==r&&r;return(0,X.jsx)(X.Fragment,{children:(0,X.jsx)("a",{href:b(n),target:"_blank",rel:"noreferrer",children:y(n,i)})})},Fe=r(70164),_e=r(35020),He=r(98649),Ue=r(37514),Ge=function(e){var n=e.numRenderedColumns,r=e.isLoading,i=void 0!==r&&r,t=e.isError,a=void 0!==t&&t,s=e.isNoData,o=void 0!==s&&s,c=e.errorEmptyState,l=void 0===c?null:c,d=e.noDataEmptyState,u=void 0===d?null:d,h=e.children,g=(0,X.jsxs)(ge.u,{variant:ge.I.sm,children:[(0,X.jsx)(pe.k,{icon:He.ZP,color:Ue.a.value}),(0,X.jsx)(L.D,{headingLevel:"h2",size:"lg",children:"Unable to connect"}),(0,X.jsx)(xe.B,{children:"There was an error retrieving data. Check your connection and try again."})]}),v=(0,X.jsxs)(ge.u,{variant:ge.I.sm,children:[(0,X.jsx)(pe.k,{icon:_e.ZP}),(0,X.jsx)(L.D,{headingLevel:"h2",size:"lg",children:"No data available"}),(0,X.jsx)(xe.B,{children:"No data available to be shown here."})]});return(0,X.jsx)(X.Fragment,{children:i?(0,X.jsx)(Se.p,{children:(0,X.jsx)(Te.Tr,{children:(0,X.jsx)(we.Td,{colSpan:n,children:(0,X.jsx)(K.b,{children:(0,X.jsx)(Fe.$,{size:"xl"})})})})}):a?(0,X.jsx)(Se.p,{"aria-label":"Table error",children:(0,X.jsx)(Te.Tr,{children:(0,X.jsx)(we.Td,{colSpan:n,children:(0,X.jsx)(K.b,{children:l||g})})})}):o?(0,X.jsx)(Se.p,{"aria-label":"Table no data",children:(0,X.jsx)(Te.Tr,{children:(0,X.jsx)(we.Td,{colSpan:n,children:(0,X.jsx)(K.b,{children:u||v})})})}):h})},Ve=function(e){var n=e.packageName;e.cves;return(0,X.jsxs)(X.Fragment,{children:[(0,X.jsx)(z.J,{isInline:!0,status:"success",children:(0,X.jsx)("img",{src:re,alt:"Security Check Icon"})}),"\xa0",(0,X.jsx)("a",{href:I(n),target:"_blank",rel:"noreferrer",children:C(n)})]})},Ye=function(){var e=fn().providerPrivateData;return{hideIssue:function(n,r){return!(!e||-1===e.indexOf(n))&&r}}},Je=function(e){var n,r,i,t=e.sourceName,a=e.vulnerability,s=Ye(),o=fn();return(0,X.jsx)(X.Fragment,{children:s.hideIssue(t,a.unique)?(0,X.jsxs)(X.Fragment,{children:[(0,X.jsx)("a",{href:o.snykSignup,target:"_blank",rel:"noreferrer",children:"Sign up for a Snyk account"})," ","to learn about the vulnerabilities found"]}):"snyk"!==t||null!==(null===(n=a.remediation)||void 0===n?void 0:n.fixedIn)&&0!==(null===(r=a.remediation)||void 0===r||null===(i=r.fixedIn)||void 0===i?void 0:i.length)?(0,X.jsx)("a",{href:M(t,a.id,o),target:"_blank",rel:"noreferrer",children:a.id}):(0,X.jsx)("p",{})})},We=r(30736),Qe=r(75351),Ke=r(30975),qe=r(6647),Xe=function(e){var n,r=e.vulnerability;switch(r.severity){case"CRITICAL":case"HIGH":n=We.n9.danger;break;default:n=We.n9.warning}return(0,X.jsx)(X.Fragment,{children:(0,X.jsx)(Qe.P,{hasGutter:!0,children:(0,X.jsx)(Ke.J,{isFilled:!0,children:(0,X.jsx)(qe.E,{title:"".concat(r.cvssScore,"/10"),"aria-label":"cvss-score",value:r.cvssScore,min:0,max:10,size:qe.L.sm,variant:n,measureLocation:We.nK.none})})})})},$e=r(30313),en=function(e){var n,r=e.vulnerability;switch(r.severity){case"CRITICAL":n="#800000";break;case"HIGH":n="#FF0000";break;case"MEDIUM":n="#FFA500";break;case"LOW":n="#5BA352";break;default:n="grey"}return(0,X.jsxs)(X.Fragment,{children:[(0,X.jsx)(z.J,{isInline:!0,children:(0,X.jsx)($e.ZP,{style:{fill:n,height:"13px"}})}),"\xa0",T(r.severity)]})},nn=function(e){var n,r,i=e.id,t=fn();return(0,X.jsx)("a",{href:(n=i,r=t,r.cveIssueTemplate.replace(v,n)),target:"_blank",rel:"noreferrer",children:i})},rn=r(84150),tn=function(e){var n=e.title,r=i.useState(!1),t=(0,ce.Z)(r,2),a=t[0],s=t[1];return(0,X.jsx)(rn.L,{variant:rn.S.truncate,toggleText:a?"Show less":"Show more",onToggle:function(e,n){s(n)},isExpanded:a,children:n})},an=function(e){var n,r,i,t,a,s=e.item,o=e.providerName,c=e.rowIndex;a=s.vulnerability.cves&&s.vulnerability.cves.length>0?s.vulnerability.cves:[s.vulnerability.id];var l=Ye().hideIssue(o,s.vulnerability.unique),d=fn();return(0,X.jsxs)(Te.Tr,{children:[l?(0,X.jsx)(X.Fragment,{children:(0,X.jsx)(we.Td,{colSpan:3,children:(0,X.jsx)("a",{href:d.snykSignup,target:"_blank",rel:"noreferrer",children:"Sign up for a Snyk account to learn about the vulnerabilities found"})})}):(0,X.jsxs)(X.Fragment,{children:[(0,X.jsx)(we.Td,{children:a.map((function(e,n){return(0,X.jsx)("p",{children:(0,X.jsx)(nn,{id:e})},n)}))}),(0,X.jsx)(we.Td,{children:(0,X.jsx)(tn,{title:s.vulnerability.title})}),(0,X.jsx)(we.Td,{noPadding:!0,children:(0,X.jsx)(en,{vulnerability:s.vulnerability})})]}),(0,X.jsx)(we.Td,{children:(0,X.jsx)(Xe,{vulnerability:s.vulnerability})}),(0,X.jsx)(we.Td,{children:(0,X.jsx)(Re,{name:s.dependencyRef,showVersion:!0})}),(0,X.jsx)(we.Td,{children:null!==(n=s.vulnerability.remediation)&&void 0!==n&&n.trustedContent?(0,X.jsx)(Ve,{cves:s.vulnerability.cves||[],packageName:null===(r=s.vulnerability.remediation)||void 0===r||null===(i=r.trustedContent)||void 0===i?void 0:i.ref},c):null!==(t=s.vulnerability.remediation)&&void 0!==t&&t.fixedIn?(0,X.jsx)(Je,{sourceName:o,vulnerability:s.vulnerability}):O(s.vulnerability)?null:(0,X.jsx)("span",{})})]},c)},sn=function(e){var n=e.providerName,r=e.transitiveDependencies;return(0,X.jsx)(B.Z,{style:{backgroundColor:"var(--pf-v5-global--BackgroundColor--100)"},children:(0,X.jsxs)(be.i,{variant:Ce.B.compact,children:[(0,X.jsx)(Me.h,{children:(0,X.jsxs)(Te.Tr,{children:[(0,X.jsx)(Ae.Th,{width:15,children:"Vulnerability ID"}),(0,X.jsx)(Ae.Th,{width:20,children:"Description"}),(0,X.jsx)(Ae.Th,{width:10,children:"Severity"}),(0,X.jsx)(Ae.Th,{width:15,children:"CVSS Score"}),(0,X.jsx)(Ae.Th,{width:20,children:"Transitive Dependency"}),(0,X.jsx)(Ae.Th,{width:20,children:"Remediation"})]})}),(0,X.jsx)(Ge,{isNoData:0===r.length,numRenderedColumns:7,children:Z(r).map((function(e,r){return(0,X.jsx)(Se.p,{children:(0,X.jsx)(an,{item:e,providerName:n,rowIndex:r})},r)}))})]})})},on=function(e){var n=e.providerName,r=e.dependency,i=e.vulnerabilities;return(0,X.jsx)(B.Z,{style:{backgroundColor:"var(--pf-v5-global--BackgroundColor--100)"},children:(0,X.jsxs)(be.i,{variant:Ce.B.compact,children:[(0,X.jsx)(Me.h,{children:(0,X.jsxs)(Te.Tr,{children:[(0,X.jsx)(Ae.Th,{width:15,children:"Vulnerability ID"}),(0,X.jsx)(Ae.Th,{width:20,children:"Description"}),(0,X.jsx)(Ae.Th,{width:10,children:"Severity"}),(0,X.jsx)(Ae.Th,{width:15,children:"CVSS Score"}),(0,X.jsx)(Ae.Th,{width:20,children:"Direct Dependency"}),(0,X.jsx)(Ae.Th,{width:20,children:"Remediation"})]})}),(0,X.jsx)(Ge,{isNoData:0===i.length,numRenderedColumns:6,children:null===i||void 0===i?void 0:i.map((function(e,i){var t=[];return e.cves&&e.cves.length>0?e.cves.forEach((function(e){return t.push(e)})):e.unique&&t.push(e.id),(0,X.jsx)(Se.p,{children:t.map((function(t,a){return(0,X.jsx)(an,{item:{id:e.id,dependencyRef:r.ref,vulnerability:e},providerName:n,rowIndex:i},"".concat(i,"-").concat(a))}))},i)}))})]})})},cn=r(63566),ln=function(e){var n=e.vulnerabilities,r=void 0===n?[]:n,i=e.transitiveDependencies,t=void 0===i?[]:i,a={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};return r.length>0?r.forEach((function(e){var n=e.severity;a.hasOwnProperty(n)&&a[n]++})):null===t||void 0===t||t.forEach((function(e){var n;null===(n=e.issues)||void 0===n||n.forEach((function(e){var n=e.severity;a.hasOwnProperty(n)&&a[n]++}))})),(0,X.jsxs)(cn.B,{children:[a.CRITICAL>0&&(0,X.jsxs)(X.Fragment,{children:[(0,X.jsx)(z.J,{isInline:!0,children:(0,X.jsx)($e.ZP,{style:{fill:"#800000",height:"13px"}})}),"\xa0",a.CRITICAL,"\xa0"]}),a.HIGH>0&&(0,X.jsxs)(X.Fragment,{children:[(0,X.jsx)(z.J,{isInline:!0,children:(0,X.jsx)($e.ZP,{style:{fill:"#FF0000",height:"13px"}})}),"\xa0",a.HIGH,"\xa0"]}),a.MEDIUM>0&&(0,X.jsxs)(X.Fragment,{children:[(0,X.jsx)(z.J,{isInline:!0,children:(0,X.jsx)($e.ZP,{style:{fill:"#FFA500",height:"13px"}})}),"\xa0",a.MEDIUM,"\xa0"]}),a.LOW>0&&(0,X.jsxs)(X.Fragment,{children:[(0,X.jsx)(z.J,{isInline:!0,children:(0,X.jsx)($e.ZP,{style:{fill:"#5BA352",height:"13px"}})}),"\xa0",a.LOW]})]})},dn=r(56934),un=function(e){var n,r,i=e.dependency,t=null===(n=i.issues)||void 0===n?void 0:n.some((function(e){return O(e)})),a=(null===(r=i.transitive)||void 0===r?void 0:r.some((function(e){var n;return null===(n=e.issues)||void 0===n?void 0:n.some((function(e){return O(e)}))})))||!1;return(0,X.jsx)(X.Fragment,{children:t||a?"Yes":"No"})},hn=function(e){var n=e.name,r=e.dependencies,t=(0,i.useState)(""),a=(0,ce.Z)(t,2),s=a[0],o=a[1],c=function(e){var n=(0,i.useReducer)(Le,(0,he.Z)((0,he.Z)({},Ze),{},{currentPage:e&&e.page?(0,he.Z)({},e.page):(0,he.Z)({},Ze.currentPage),sortBy:e&&e.sortBy?(0,he.Z)({},e.sortBy):Ze.sortBy})),r=(0,ce.Z)(n,2),t=r[0],a=r[1],s=(0,i.useCallback)((function(e){var n;a({type:Oe.SET_PAGE,payload:{page:e.page>=1?e.page:1,perPage:null!==(n=e.perPage)&&void 0!==n?n:Ze.currentPage.perPage}})}),[]),o=(0,i.useCallback)((function(e,n,r,i){a({type:Oe.SET_SORT_BY,payload:{index:n,direction:r}})}),[]);return{page:t.currentPage,sortBy:t.sortBy,changePage:s,changeSortBy:o}}(),l=c.page,d=c.sortBy,u=c.changePage,h=c.changeSortBy,g=function(e){var n=e.items,r=e.currentSortBy,t=e.currentPage,a=e.filterItem,s=e.compareToByColumn;return(0,i.useMemo)((function(){var e,i=(0,Pe.Z)(n||[]).filter(a),o=!1;return e=(0,Pe.Z)(i).sort((function(e,n){var i=s(e,n,null===r||void 0===r?void 0:r.index);return 0!==i&&(o=!0),i})),o&&(null===r||void 0===r?void 0:r.direction)===ke.B.desc&&(e=e.reverse()),{pageItems:e.slice((t.page-1)*t.perPage,t.page*t.perPage),filteredItems:i}}),[n,t,r,s,a])}({items:r,currentPage:l,currentSortBy:d,compareToByColumn:function(e,n,r){return 1===r?e.ref.localeCompare(n.ref):0},filterItem:function(e){var n=!0;return s&&s.trim().length>0&&(n=-1!==e.ref.toLowerCase().indexOf(s.toLowerCase())),n}}),v=g.pageItems,p=g.filteredItems,x={name:"Dependency Name",version:"Current Version",direct:"Direct Vulnerabilities",transitive:"Transitive Vulnerabilities",rhRemediation:"Remediation available"},j=i.useState({"siemur/test-space":"name"}),f=(0,ce.Z)(j,2),y=f[0],I=f[1],b=function(e,n,r,i){return{isExpanded:y[e.ref]===n,onToggle:function(){return function(e,n){var r=!(arguments.length>2&&void 0!==arguments[2])||arguments[2],i=(0,he.Z)({},y);r?i[e.ref]=n:delete i[e.ref],I(i)}(e,n,y[e.ref]!==n)},expandId:"compound-expandable-example",rowIndex:r,columnIndex:i}};return(0,X.jsx)(B.Z,{children:(0,X.jsx)(H.e,{children:(0,X.jsx)("div",{style:{backgroundColor:"var(--pf-v5-global--BackgroundColor--100)"},children:""!==m(n)&&void 0===r?(0,X.jsx)("div",{children:(0,X.jsxs)(ge.u,{variant:ge.I.sm,children:[(0,X.jsx)(ve.t,{icon:(0,X.jsx)(pe.k,{icon:_e.ZP}),titleText:"Set up "+n,headingLevel:"h2"}),(0,X.jsxs)(xe.B,{children:["You need to provide a valid credentials to see ",n," data. You can use the button below to sing-up for ",n,". If you have already signed up, enter your credentials in your extension settings and then regenerate the Dependency Analytics report."]}),(0,X.jsx)("br",{}),(0,X.jsx)("br",{}),(0,X.jsx)("a",{href:m(n),target:"_blank",rel:"noopener noreferrer",children:(0,X.jsxs)(W.zx,{variant:"primary",size:"sm",children:["Sign up for ",n]})})]})}):(0,X.jsxs)(X.Fragment,{children:[(0,X.jsx)(je.o,{children:(0,X.jsxs)(fe.c,{children:[(0,X.jsx)(me.R,{toggleIcon:(0,X.jsx)(Ne.ZP,{}),breakpoint:"xl",children:(0,X.jsx)(ye.E,{variant:"search-filter",children:(0,X.jsx)(Ie.M,{style:{width:"250px"},placeholder:"Filter by Dependency name",value:s,onChange:function(e,n){return o(n)},onClear:function(){return o("")}})})}),(0,X.jsx)(ye.E,{variant:ye.A.pagination,align:{default:"alignRight"},children:(0,X.jsx)(Be,{isTop:!0,count:p.length,params:l,onChange:u})})]})}),(0,X.jsxs)(be.i,{"aria-label":"Compound expandable table",variant:Ce.B.compact,children:[(0,X.jsx)(Me.h,{children:(0,X.jsxs)(Te.Tr,{children:[(0,X.jsx)(Ae.Th,{width:25,sort:{columnIndex:1,sortBy:(0,he.Z)({},d),onSort:h},children:x.name}),(0,X.jsx)(Ae.Th,{children:x.version}),(0,X.jsx)(Ae.Th,{children:x.direct}),(0,X.jsx)(Ae.Th,{children:x.transitive}),(0,X.jsx)(Ae.Th,{children:x.rhRemediation})]})}),(0,X.jsx)(Ge,{isNoData:0===p.length,numRenderedColumns:8,noDataEmptyState:(0,X.jsxs)(ge.u,{variant:ge.I.sm,children:[(0,X.jsx)(ve.t,{icon:(0,X.jsx)(pe.k,{icon:dn.ZP}),titleText:"No results found",headingLevel:"h2"}),(0,X.jsx)(xe.B,{children:"Clear all filters and try again."})]}),children:null===v||void 0===v?void 0:v.map((function(e,r){var i,t,a,s,o,c=y[e.ref],l=!!c;return null!==(i=e.issues)&&void 0!==i&&i.length||null!==(t=e.transitive)&&void 0!==t&&t.length?(0,X.jsxs)(Se.p,{isExpanded:l,children:[(0,X.jsxs)(Te.Tr,{children:[(0,X.jsx)(we.Td,{width:30,dataLabel:x.name,component:"th",children:(0,X.jsx)(Re,{name:e.ref})}),(0,X.jsx)(we.Td,{width:15,dataLabel:x.version,children:C(e.ref)}),(0,X.jsx)(we.Td,{width:15,dataLabel:x.direct,compoundExpand:b(e,"direct",r,2),children:null!==(a=e.issues)&&void 0!==a&&a.length?(0,X.jsxs)("div",{style:{display:"flex",alignItems:"center"},children:[(0,X.jsx)("div",{style:{width:"25px"},children:null===(s=e.issues)||void 0===s?void 0:s.length}),(0,X.jsx)(E.i,{orientation:{default:"vertical"},style:{paddingRight:"10px"}}),(0,X.jsx)(ln,{vulnerabilities:e.issues})]}):0}),(0,X.jsx)(we.Td,{width:15,dataLabel:x.transitive,compoundExpand:b(e,"transitive",r,3),children:null!==(o=e.transitive)&&void 0!==o&&o.length?(0,X.jsxs)("div",{style:{display:"flex",alignItems:"center"},children:[(0,X.jsx)("div",{style:{width:"25px"},children:e.transitive.map((function(e){var n;return null===(n=e.issues)||void 0===n?void 0:n.length})).reduce((function(){return(arguments.length>0&&void 0!==arguments[0]?arguments[0]:0)+(arguments.length>1&&void 0!==arguments[1]?arguments[1]:0)}))}),(0,X.jsx)(E.i,{orientation:{default:"vertical"},style:{paddingRight:"10px"}}),(0,X.jsx)(ln,{transitiveDependencies:e.transitive})]}):0}),(0,X.jsx)(we.Td,{width:15,dataLabel:x.rhRemediation,children:(0,X.jsx)(un,{dependency:e})})]}),l?(0,X.jsx)(Te.Tr,{isExpanded:l,children:(0,X.jsx)(we.Td,{dataLabel:x[c],noPadding:!0,colSpan:6,children:(0,X.jsx)(De.G,{children:(0,X.jsx)("div",{className:"pf-v5-u-m-md",children:"direct"===c&&e.issues&&e.issues.length>0?(0,X.jsx)(on,{providerName:n,dependency:e,vulnerabilities:e.issues}):"transitive"===c&&e.transitive&&e.transitive.length>0?(0,X.jsx)(sn,{providerName:n,transitiveDependencies:e.transitive}):null})})})}):null]},e.ref):null}))})]}),(0,X.jsx)(Be,{isTop:!1,count:p.length,params:l,onChange:u}),"osv-nvd"===n&&(0,X.jsx)("div",{children:(0,X.jsx)("p",{children:"Disclaimer:This Product uses data from the NVD API but is not endorsed or certified by the NVD"})})]})})})})},gn=r(61602),vn=function(e){var n=e.report,r=fn(),t=P(n),s=i.useState(k(t[0])),o=(0,ce.Z)(s,2),c=o[0],l=o[1],d=i.useState(!0),u=(0,ce.Z)(d,1)[0],h=r.writeKey&&""!==r.writeKey.trim()?gn.b.load({writeKey:r.writeKey}):null,g=(0,i.useRef)(""),v=(0,i.useRef)(!1);(0,i.useEffect)((function(){h&&!v.current&&(null!=r.userId?h.identify(r.userId):null!=r.anonymousId&&h.setAnonymousId(r.anonymousId),v.current=!0)}),[]),(0,i.useEffect)((function(){if(h){var e=function(){var e=(0,oe.Z)((0,se.Z)().mark((function e(n){return(0,se.Z)().wrap((function(e){for(;;)switch(e.prev=e.next){case 0:n!==g.current&&(h.track("rhda.exhort.tab",{tabName:n}),g.current=n);case 1:case"end":return e.stop()}}),e)})));return function(n){return e.apply(this,arguments)}}();e(c)}}),[c,h]);var p=t.map((function(e){var n,r=k(e),i=null===(n=e.report.dependencies)||void 0===n?void 0:n.filter((function(e){return e.highestVulnerability}));return(0,X.jsx)(le.O,{eventKey:r,title:(0,X.jsx)(de.T,{children:r}),"aria-label":"".concat(r," source"),children:(0,X.jsx)(a.NP,{variant:a.Dk.default,children:(0,X.jsx)(hn,{name:r,dependencies:i})})})}));return(0,X.jsx)("div",{children:(0,X.jsx)(ue.m,{activeKey:c,onSelect:function(e,n){l(n)},"aria-label":"Providers",role:"region",variant:u?"light300":"default",isBox:!0,children:p})})},pn=function(e){var n=e.report,r=i.useState(Object.keys(n)[0]||""),t=(0,ce.Z)(r,2),c=t[0],l=t[1],d=i.useState(!0),u=(0,ce.Z)(d,1)[0],h=Object.entries(n).map((function(e){var n=(0,ce.Z)(e,2),r=n[0],i=n[1];return(0,X.jsxs)(le.O,{eventKey:r,title:(0,X.jsx)(de.T,{children:A(r)}),"aria-label":"".concat(r," source"),children:[(0,X.jsx)(ae,{report:i}),(0,X.jsx)(a.NP,{variant:a.Dk.light,children:(0,X.jsx)(s.r,{hasGutter:!0,children:(0,X.jsx)(o.P,{children:(0,X.jsx)(ie,{report:i,isReportMap:!0,purl:r})})})}),(0,X.jsx)(a.NP,{variant:a.Dk.default,children:(0,X.jsx)(vn,{report:i})})]})}));return(0,X.jsx)("div",{children:(0,X.jsx)(ue.m,{activeKey:c,onSelect:function(e,n){l(n)},"aria-label":"Providers",role:"region",variant:u?"light300":"default",isBox:!0,children:h})})},xn=window.appData,jn=(0,i.createContext)(xn),fn=function(){return(0,i.useContext)(jn)};var mn=function(){return(0,X.jsx)(jn.Provider,{value:xn,children:(e=xn.report,"object"===typeof e&&null!==e&&Object.keys(e).every((function(n){return"scanned"in e[n]&&"providers"in e[n]&&"object"===typeof e[n].scanned&&"object"===typeof e[n].providers}))?(0,X.jsx)(a.NP,{variant:a.Dk.default,children:(0,X.jsx)(pn,{report:xn.report})}):(0,X.jsxs)(X.Fragment,{children:[(0,X.jsx)(ae,{report:xn.report}),(0,X.jsx)(a.NP,{variant:a.Dk.light,children:(0,X.jsx)(s.r,{hasGutter:!0,children:(0,X.jsx)(o.P,{children:(0,X.jsx)(ie,{report:xn.report})})})}),(0,X.jsx)(a.NP,{variant:a.Dk.default,children:(0,X.jsx)(vn,{report:xn.report})})]}))});var e},yn=function(e){e&&e instanceof Function&&r.e(736).then(r.bind(r,40599)).then((function(n){var r=n.getCLS,i=n.getFID,t=n.getFCP,a=n.getLCP,s=n.getTTFB;r(e),i(e),t(e),a(e),s(e)}))};t.createRoot(document.getElementById("root")).render((0,X.jsx)(i.StrictMode,{children:(0,X.jsx)(mn,{})})),yn()}},n={};function r(i){var t=n[i];if(void 0!==t)return t.exports;var a=n[i]={id:i,loaded:!1,exports:{}};return e[i].call(a.exports,a,a.exports,r),a.loaded=!0,a.exports}r.m=e,function(){var e=[];r.O=function(n,i,t,a){if(!i){var s=1/0;for(d=0;d<e.length;d++){i=e[d][0],t=e[d][1],a=e[d][2];for(var o=!0,c=0;c<i.length;c++)(!1&a||s>=a)&&Object.keys(r.O).every((function(e){return r.O[e](i[c])}))?i.splice(c--,1):(o=!1,a<s&&(s=a));if(o){e.splice(d--,1);var l=t();void 0!==l&&(n=l)}}return n}a=a||0;for(var d=e.length;d>0&&e[d-1][2]>a;d--)e[d]=e[d-1];e[d]=[i,t,a]}}(),r.n=function(e){var n=e&&e.__esModule?function(){return e.default}:function(){return e};return r.d(n,{a:n}),n},function(){var e,n=Object.getPrototypeOf?function(e){return Object.getPrototypeOf(e)}:function(e){return e.__proto__};r.t=function(i,t){if(1&t&&(i=this(i)),8&t)return i;if("object"===typeof i&&i){if(4&t&&i.__esModule)return i;if(16&t&&"function"===typeof i.then)return i}var a=Object.create(null);r.r(a);var s={};e=e||[null,n({}),n([]),n(n)];for(var o=2&t&&i;"object"==typeof o&&!~e.indexOf(o);o=n(o))Object.getOwnPropertyNames(o).forEach((function(e){s[e]=function(){return i[e]}}));return s.default=function(){return i},r.d(a,s),a}}(),r.d=function(e,n){for(var i in n)r.o(n,i)&&!r.o(e,i)&&Object.defineProperty(e,i,{enumerable:!0,get:n[i]})},r.e=function(){return Promise.resolve()},r.g=function(){if("object"===typeof globalThis)return globalThis;try{return this||new Function("return this")()}catch(e){if("object"===typeof window)return window}}(),r.o=function(e,n){return Object.prototype.hasOwnProperty.call(e,n)},r.r=function(e){"undefined"!==typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},r.nmd=function(e){return e.paths=[],e.children||(e.children=[]),e},function(){var e={179:0};r.O.j=function(n){return 0===e[n]};var n=function(n,i){var t,a,s=i[0],o=i[1],c=i[2],l=0;if(s.some((function(n){return 0!==e[n]}))){for(t in o)r.o(o,t)&&(r.m[t]=o[t]);if(c)var d=c(r)}for(n&&n(i);l<s.length;l++)a=s[l],r.o(e,a)&&e[a]&&e[a][0](),e[a]=0;return r.O(d)},i=self.webpackChunkui=self.webpackChunkui||[];i.forEach(n.bind(null,0)),i.push=n.bind(null,i.push.bind(i))}();var i=r.O(void 0,[736],(function(){return r(31958)}));i=r.O(i)}();