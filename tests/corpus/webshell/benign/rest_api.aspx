<%@ Page Language="C#" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e) {
    Response.ContentType = "application/json";
    Response.Write("{\"status\":\"ok\"}");
}
</script>
