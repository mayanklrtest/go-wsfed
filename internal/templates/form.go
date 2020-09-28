package templates

import "html/template"

func WSFedPostForm() *template.Template {
	return template.Must(template.New("wsfed-post-form").Parse(`<html>` +
		`<form method="post" action="{{.Wreply}}" id="WsFedResponseForm">` +
		`<input type="hidden" name="wa" value="wsignin1.0" />` +
		`<input type="hidden" name="wresult" value="{{.Wresult}}" />` +
		`<input type="hidden" name="wctx" value="{{.Wctx}}" />` +
		`<input id="WsFedSubmitButton" type="submit" value="Continue" />` +
		`</form>` +
		`<script>document.getElementById('WsFedSubmitButton').style.visibility='hidden';</script>` +
		`<script>document.getElementById('WsFedResponseForm').submit();</script>` +
		`</html>`))
}
