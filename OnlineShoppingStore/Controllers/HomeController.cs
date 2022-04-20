using Newtonsoft.Json;
using OnlineShoppingStore.DAL;
using OnlineShoppingStore.Models;
using OnlineShoppingStore.Models.Home;
using OnlineShoppingStore.Repository;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using OnlineShoppingStore.Controllers;




namespace OnlineShoppingStore.Controllers
{
    public class HomeController : Controller
    {
        dbMyOnlineShoppingEntities ctx = new dbMyOnlineShoppingEntities();
        public ActionResult Index(string search,int? page)
        {
            HomeIndexViewModel model = new HomeIndexViewModel();
            return View(model.CreateModel(search,4, page));
        }
        public ActionResult Checkout()
        {
            return View();
        }


       

        public ActionResult CheckoutDetails()
        {
            return View();
        }
        public ActionResult DecreaseQty(int productId)
        {
            if (Session["cart"] != null)
            {
                List<Item> cart = (List<Item>)Session["cart"];
                var product = ctx.Tbl_Product.Find(productId);
                foreach (var item in cart)
                {
                    if (item.Product.ProductId == productId)
                    {
                        int prevQty = item.Quantity;
                        if (prevQty > 0)
                        {
                            cart.Remove(item);
                            cart.Add(new Item()
                            {
                                Product = product,
                                Quantity = prevQty - 1
                            });
                        }
                        break;
                    }
                }
                Session["cart"] = cart;
            }
            return Redirect("Checkout");
        }
        public ActionResult AddToCart(int productId,string url)
        {
            if (Session["cart"] == null)
            {
                List<Item> cart = new List<Item>();
                var product = ctx.Tbl_Product.Find(productId);
                cart.Add(new Item()
                {
                    Product = product,
                    Quantity = 1
                });
                Session["cart"] = cart;
            }
            else
            {
                List<Item> cart = (List<Item>)Session["cart"];
                var count = cart.Count();
                var product = ctx.Tbl_Product.Find(productId);
                for (int i = 0; i < count;i++ )
                {
                    if (cart[i].Product.ProductId == productId)
                    {
                        int prevQty = cart[i].Quantity;
                        cart.Remove(cart[i]);
                        cart.Add(new Item()
                        {
                            Product = product,
                            Quantity = prevQty + 1
                        });
                        break;
                    }
                    else
                    {
                        var prd = cart.Where(x => x.Product.ProductId == productId).SingleOrDefault();
                        if (prd == null)
                        {
                            cart.Add(new Item()
                            {
                                Product = product,
                                Quantity = 1
                            });
                        }
                    }
                }
                Session["cart"] = cart;
            }
            return Redirect(url);
        }
        public ActionResult RemoveFromCart(int productId)
        {
            List<Item> cart = (List<Item>)Session["cart"];
            foreach (var item in cart)
            {
                if (item.Product.ProductId == productId)
                {
                    cart.Remove(item);
                    break;
                }
            }
            Session["cart"] = cart;
            return Redirect("Index");
        }
        public ActionResult ContactUs()
        {
            return View();
        }
        public ActionResult About()
        {
            return View();
        }

        //[HttpPost]
        //public ActionResult ContactUs(contract)
        //{
        //    ////Read SMTP section from Web.Config.
        //    //SmtpSection smtpSection = (SmtpSection)ConfigurationManager.GetSection("system.net/mailSettings/smtp");

        //    //using (MailMessage mm = new MailMessage(smtpSection.From, "admin@aspsnippets.com"))
        //    //{
        //    //    mm.Subject = model.Subject;
        //    //    mm.Body = "Name: " + model.Name + "<br /><br />Email: " + model.Email + "<br />" + model.Body;
        //    //    if (model.Attachment.ContentLength > 0)
        //    //    {
        //    //        string fileName = Path.GetFileName(model.Attachment.FileName);
        //    //        mm.Attachments.Add(new Attachment(model.Attachment.InputStream, fileName));
        //    //    }
        //    //    mm.IsBodyHtml = true;

        //    //    using (SmtpClient smtp = new SmtpClient())
        //    //    {
        //    //        smtp.Host = smtpSection.Network.Host;
        //    //        smtp.EnableSsl = smtpSection.Network.EnableSsl;
        //    //        NetworkCredential networkCred = new NetworkCredential(smtpSection.Network.UserName, smtpSection.Network.Password);
        //    //        smtp.UseDefaultCredentials = true;
        //    //        smtp.Credentials = networkCred;
        //    //        smtp.Port = smtpSection.Network.Port;
        //    //        smtp.Send(mm);
        //    //        ViewBag.Message = "Email sent sucessfully.";
        //    //    }
        //    //}

        //    return View();
        //}
    }
}