﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace AccesoBolsaTrabajo3.Models
{
    using System;
    using System.Data.Entity;
    using System.Data.Entity.Infrastructure;
    
    public partial class DataBaseSAGAEntitiesValidation : DbContext
    {
        public DataBaseSAGAEntitiesValidation()
            : base("name=DataBaseSAGAEntitiesValidation")
        {
        }
    
        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            throw new UnintentionalCodeFirstException();
        }
    
        public virtual DbSet<FormulariosIniciale> FormulariosIniciales { get; set; }
        public virtual DbSet<AspNetUser> AspNetUsers { get; set; }
    }
}
