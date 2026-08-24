import { redirect } from "next/navigation";

// Exposures is the reason the product exists, so it is the front door.
export default function Home() {
  redirect("/exposures");
}
