﻿// <auto-generated />
using System;
using MaxSecurityWAF;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

#nullable disable

namespace MaxSecurityWAF.Migrations
{
    [DbContext(typeof(WAFContext))]
    partial class WAFContextModelSnapshot : ModelSnapshot
    {
        protected override void BuildModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder.HasAnnotation("ProductVersion", "7.0.11");

            modelBuilder.Entity("MaxSecurityWAF.LogEntry", b =>
                {
                    b.Property<int>("LogEntryId")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("INTEGER");

                    b.Property<int>("Result")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SourceIP")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("Timestamp")
                        .HasColumnType("TEXT");

                    b.Property<string>("Url")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("LogEntryId");

                    b.HasIndex("Timestamp");

                    b.ToTable("LogEntries");
                });

            modelBuilder.Entity("MaxSecurityWAF.User", b =>
                {
                    b.Property<int>("UserId")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("INTEGER");

                    b.Property<string>("Password")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Username")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("UserId");

                    b.HasIndex("Username");

                    b.ToTable("Users");

                    b.HasData(
                        new
                        {
                            UserId = -1,
                            Password = "P4geAuE2yX/PDRHuJSq74FF5vO782rWz5c0LAQPR8m45DEYAONhu1wYnAn60PSNyjocqEBdnCeKCJfK3sKyuWw==",
                            Username = "admin"
                        });
                });

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
