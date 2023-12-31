﻿// <auto-generated />
using MaxSecurityWAF;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

#nullable disable

namespace MaxSecurityWAF.Migrations
{
    [DbContext(typeof(WAFContext))]
    [Migration("20230914100632_RuleEnabled")]
    partial class RuleEnabled
    {
        /// <inheritdoc />
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder.HasAnnotation("ProductVersion", "7.0.10");

            modelBuilder.Entity("MaxSecurityWAF.WAFRule", b =>
                {
                    b.Property<int>("WAFRuleId")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("INTEGER");

                    b.Property<int>("Action")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("Enabled")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Path")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("SourceIP")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("WAFRuleId");

                    b.ToTable("Rules");
                });
#pragma warning restore 612, 618
        }
    }
}
