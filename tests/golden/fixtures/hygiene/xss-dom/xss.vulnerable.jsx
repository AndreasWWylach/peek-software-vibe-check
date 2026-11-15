// Golden fixture: XSS hygiene rule must fire on React's dangerous escape hatch.
function Bad({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
